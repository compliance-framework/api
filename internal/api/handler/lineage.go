package handler

import (
	"errors"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/leverage"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// LineageHandler serves the read-only lineage API: it walks
// Standard -> Policy -> Controls -> Evidence (with Risks attached) and returns
// per-node compliance % and risk score sums, filterable by SSP and Component.
type LineageHandler struct {
	sugar      *zap.SugaredLogger
	db         *gorm.DB
	pagination *svc.PaginationConfig
}

func NewLineageHandler(l *zap.SugaredLogger, db *gorm.DB) *LineageHandler {
	return &LineageHandler{
		sugar:      l,
		db:         db,
		pagination: svc.NewPaginationConfig(),
	}
}

func (h *LineageHandler) Register(api *echo.Group, guard middleware.ResourceGuard) {
	api.GET("/roots", h.Roots, guard.Read())
	api.GET("/nodes/:key/children", h.Children, guard.Read())
	api.GET("/nodes/:key/ssps", h.SSPDetail, guard.Read())
	api.GET("/nodes/:key/leverage", h.LeverageDetail, guard.Read())
}

// ── Response shapes ────────────────────────────────────────────────────────────

// LineageCompliance is a node's compliance rollup.
//
// NOTE on TotalControls (and the two percentages, which share its denominator):
// its unit depends on scope. In single-SSP scope, or globally with no SSPs, it is
// a count of distinct in-scope controls. In the global (no sspId) view WITH SSPs
// present it is a count of in-scope (control × SSP) cells — a control tracked by N
// SSPs contributes up to N — so a control failing in one plan and N/A in another
// is not collapsed. Consumers must not render it as a raw control count in that
// scope. (Satisfied/NotSatisfied/Unknown/Inherited follow the same unit.)
//
// Inherited counts cells credited to an upstream leverage link. It counts as
// compliant in CompliancePercent and as assessed in AssessedPercent; it is NOT part
// of Unknown.
type LineageCompliance struct {
	TotalControls     int     `json:"totalControls"`
	Satisfied         int     `json:"satisfied"`
	NotSatisfied      int     `json:"notSatisfied"`
	Unknown           int     `json:"unknown"`
	Inherited         int     `json:"inherited"`
	CompliancePercent float64 `json:"compliancePercent"`
	AssessedPercent   float64 `json:"assessedPercent"`
}

// LineageLeverageSummary is the compact per-(control, SSP) leverage badge carried on
// posture overlays and drawer rows. Present whenever at least one leverage link
// exists for the control in that SSP — regardless of whether it earned inherited
// credit — so the UI can badge partial/drifted leverage too. Status is the worst
// link status; Satisfaction is full iff every link is full.
type LineageLeverageSummary struct {
	Links                 int    `json:"links"`
	Status                string `json:"status"`
	Satisfaction          string `json:"satisfaction"`
	OutstandingCount      int    `json:"outstandingCount"`
	TotalResponsibilities int    `json:"totalResponsibilities"`
}

type LineageRiskCounts struct {
	Open                  int `json:"open"`
	Investigating         int `json:"investigating"`
	MitigatingPlanned     int `json:"mitigatingPlanned"`
	RiskAccepted          int `json:"riskAccepted"`
	MitigatingImplemented int `json:"mitigatingImplemented"`
}

type LineageRisk struct {
	OpenScoreSum  int               `json:"openScoreSum"`
	MutedScoreSum int               `json:"mutedScoreSum"`
	Counts        LineageRiskCounts `json:"counts"`
}

type LineageLinkage struct {
	Policies            int  `json:"policies"`
	Procedures          int  `json:"procedures"`
	OperationalControls int  `json:"operationalControls"`
	Unmapped            bool `json:"unmapped"`
	Unanchored          bool `json:"unanchored"`
}

// Posture values classify how a single control is handled within one SSP. The
// ladder is: out-of-scope wins first (control not in the SSP's profile), then
// decisive evidence (not-satisfied > satisfied), then — only when there is no
// decisive evidence — the human-declared implementation status decides whether
// the gap is a problem (attention) or expected (not-applicable / planned).
const (
	PostureOutOfScope    = "out-of-scope"
	PostureSatisfied     = "satisfied"
	PostureNotSatisfied  = "not-satisfied"
	PostureInherited     = "inherited"
	PostureNotApplicable = "not-applicable"
	PosturePlanned       = "planned"
	PostureAttention     = "attention"
)

// LineageSSPStatus overlays a control node with its posture in the selected SSP.
// Populated only for operational controls when sspId is set. It carries the raw
// inputs (profile membership, evidence status, uniform implementation status)
// alongside the derived posture so the UI can render or re-derive as needed.
type LineageSSPStatus struct {
	Posture              string                  `json:"posture"`
	InProfile            bool                    `json:"inProfile"`
	EvidenceStatus       string                  `json:"evidenceStatus"`
	ImplementationStatus string                  `json:"implementationStatus,omitempty"`
	Leverage             *LineageLeverageSummary `json:"leverage,omitempty"`
}

// LineagePostureCounts tallies the postures of a structural node's own
// operational controls in the selected SSP. Populated only when sspId is set.
// It lets the UI stop painting not-applicable/planned controls as problems
// without changing the raw compliance counts (which keep their denominator).
type LineagePostureCounts struct {
	Satisfied     int `json:"satisfied"`
	NotSatisfied  int `json:"notSatisfied"`
	Inherited     int `json:"inherited"`
	NotApplicable int `json:"notApplicable"`
	Planned       int `json:"planned"`
	Attention     int `json:"attention"`
	OutOfScope    int `json:"outOfScope"`
}

// LineageSSPBreakdown answers "across all SSPs, how is this control handled?".
// Populated only for operational control nodes in the global (no sspId) view —
// each SSP contributes exactly one posture bucket. OutOfScope is "how many SSPs
// don't include this control"; NotApplicable is "how many marked it N/A".
type LineageSSPBreakdown struct {
	TotalSSPs     int `json:"totalSsps"`
	OutOfScope    int `json:"outOfScope"`
	Satisfied     int `json:"satisfied"`
	NotSatisfied  int `json:"notSatisfied"`
	Inherited     int `json:"inherited"`
	NotApplicable int `json:"notApplicable"`
	Planned       int `json:"planned"`
	Attention     int `json:"attention"`
}

// LineageSSPRow is one row of the per-SSP drawer table for a control: how that
// control stands in one SSP — its rolled-up posture, evidence status and declared
// implementation status — so the drawer can show a plan-by-plan breakdown instead
// of a single collapsed verdict.
type LineageSSPRow struct {
	SSPID                string                  `json:"sspId"`
	SSPTitle             string                  `json:"sspTitle"`
	InProfile            bool                    `json:"inProfile"`
	Posture              string                  `json:"posture"`
	EvidenceStatus       string                  `json:"evidenceStatus"`
	ImplementationStatus string                  `json:"implementationStatus,omitempty"`
	Leverage             *LineageLeverageSummary `json:"leverage,omitempty"`
}

type LineageNode struct {
	Key      string `json:"key"`
	NodeType string `json:"nodeType"`
	// Relationship describes how this node relates to the parent it was expanded
	// from (group | control | implements | documents | has-risk | has-evidence),
	// so a node-link graph can label/style edges. Empty for roots.
	Relationship string `json:"relationship,omitempty"`
	CatalogID    string `json:"catalogId,omitempty"`
	ControlID    string `json:"controlId,omitempty"`
	GroupID      string `json:"groupId,omitempty"`
	RiskID       string `json:"riskId,omitempty"`
	EvidenceID   string `json:"evidenceId,omitempty"`
	Title        string `json:"title"`
	// Statement is the control's requirement prose (OSCAL "statement" part),
	// surfaced for hover/tooltip in the lineage tree & graph. Control nodes only.
	Statement string `json:"statement,omitempty"`
	Status    string `json:"status,omitempty"`

	// Risk-node detail.
	Severity            string     `json:"severity,omitempty"`
	Score               *int       `json:"score,omitempty"`
	Likelihood          string     `json:"likelihood,omitempty"`
	Impact              string     `json:"impact,omitempty"`
	LinkedEvidenceCount *int       `json:"linkedEvidenceCount,omitempty"`
	ReviewDeadline      *time.Time `json:"reviewDeadline,omitempty"`
	LastReviewedAt      *time.Time `json:"lastReviewedAt,omitempty"`
	FirstSeenAt         *time.Time `json:"firstSeenAt,omitempty"`
	LastSeenAt          *time.Time `json:"lastSeenAt,omitempty"`
	// RiskSSPID/RiskSSPTitle identify the single SSP a risk node belongs to
	// (risk_register_risks.ssp_id is not-null — every risk has exactly one).
	// Populated regardless of scope so the UI can group risk nodes by SSP in
	// the unscoped "All SSPs" view.
	RiskSSPID    string `json:"sspId,omitempty"`
	RiskSSPTitle string `json:"sspTitle,omitempty"`

	// Evidence-node detail.
	Reason      string     `json:"reason,omitempty"`
	CollectedAt *time.Time `json:"collectedAt,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`

	Compliance LineageCompliance `json:"compliance"`
	Risk       LineageRisk       `json:"risk"`
	Linkage    LineageLinkage    `json:"linkage"`

	// SSP-scoped posture (sspId set): SSP on operational control nodes, and
	// PostureCounts on structural nodes tallying their controls' postures.
	// SSPBreakdown replaces both in the global (no sspId) view on control nodes.
	SSP           *LineageSSPStatus     `json:"ssp,omitempty"`
	PostureCounts *LineagePostureCounts `json:"postureCounts,omitempty"`
	SSPBreakdown  *LineageSSPBreakdown  `json:"sspBreakdown,omitempty"`

	HasChildren   bool `json:"hasChildren"`
	ChildrenCount int  `json:"childrenCount"`
}

// ── Endpoints ──────────────────────────────────────────────────────────────────

// Roots godoc

// @Summary		List lineage roots
// @Description	Returns active catalog roots (standard/policy/procedure) with full-subtree compliance and risk rollups. Rootness is catalog_type, never link presence; inactive catalogs are omitted from roots but still appear as children when a control-link points into them. NOTE: with sspId omitted but SSPs present, compliance.totalControls counts in-scope (control x SSP) cells, not distinct controls (a control tracked by N SSPs counts up to N).
// @Tags			Lineage
// @Produce		json
// @Param			sspId		query		string	false	"Scope metrics to a System Security Plan"
// @Param			componentId	query		string	false	"Scope metrics to a system component"
// @Param			types		query		string	false	"Comma-separated catalog types to include (standard,policy,procedure,internal,other)"
// @Success		200			{object}	svc.ListResponse[LineageNode]
// @Failure		400			{object}	api.Error
// @Failure		500			{object}	api.Error
// @Security		OAuth2Password
// @Router			/lineage/roots [get]
func (h *LineageHandler) Roots(ctx echo.Context) error {
	sspID, componentID, err := parseScope(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	types, err := parseTypes(ctx.QueryParam("types"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	engine, err := h.buildEngine(sspID, componentID)
	if err != nil {
		h.sugar.Errorw("failed to build lineage engine", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	catalogIDs := make([]uuid.UUID, 0, len(engine.catalogs))
	for id, info := range engine.catalogs {
		// Rootness is catalog_type AND active state: inactive catalogs never appear
		// as roots, though they still surface as children when a control-link points
		// into them.
		if !info.active {
			continue
		}
		if _, ok := types[info.ctype]; ok {
			catalogIDs = append(catalogIDs, id)
		}
	}

	nodes := make([]LineageNode, 0, len(catalogIDs))
	for _, id := range catalogIDs {
		nodes = append(nodes, engine.catalogNode(id))
	}
	sortNodes(nodes)

	// Roots aren't paginated, but return the same ListResponse envelope as
	// /children so a UI consumer handles one shape across the lineage family.
	// Guard the limit against 0 (empty roots) since NewListResponse divides by it.
	limit := len(nodes)
	if limit < 1 {
		limit = 1
	}
	return ctx.JSON(http.StatusOK, svc.NewListResponse(nodes, int64(len(nodes)), 1, limit))
}

// Children godoc

// @Summary		List lineage node children
// @Description	Returns one level of children for a node. Key is a composite like catalog:<uuid>, group:<catalogId>/<groupId>, control:<catalogId>/<controlId>, linkcat:<childCatalogId>/<relationship>/<parentCatalogId>/<parentControlId>, risk:<riskId>, evidence:<streamUuid>. A control expands to synthetic linkcat catalog nodes (its implementing/documenting controls grouped by their catalog) plus its directly-linked risks; a linkcat node expands to that group's controls; a risk expands to its latest evidence per linked stream; evidence is a leaf.
// @Tags			Lineage
// @Produce		json
// @Param			key			path		string	true	"URL-encoded node key"
// @Param			sspId		query		string	false	"Scope metrics to a System Security Plan"
// @Param			componentId	query		string	false	"Scope metrics to a system component"
// @Param			page		query		int		false	"Page number"
// @Param			limit		query		int		false	"Page size (default 100)"
// @Success		200			{object}	svc.ListResponse[LineageNode]
// @Failure		400			{object}	api.Error
// @Failure		404			{object}	api.Error
// @Failure		500			{object}	api.Error
// @Security		OAuth2Password
// @Router			/lineage/nodes/{key}/children [get]
func (h *LineageHandler) Children(ctx echo.Context) error {
	sspID, componentID, err := parseScope(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	// Default the page size to 100 per the lineage contract.
	limitCfg := *h.pagination
	limitCfg.DefaultLimit = 100
	pagination, err := limitCfg.ParseParams(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	kind, catalogID, subID, err := parseNodeKey(ctx.Param("key"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	engine, err := h.buildEngine(sspID, componentID)
	if err != nil {
		h.sugar.Errorw("failed to build lineage engine", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	children, err := engine.childrenOf(kind, catalogID, subID)
	if err != nil {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	sortNodes(children)

	total := int64(len(children))
	start := pagination.Offset
	if start > len(children) {
		start = len(children)
	}
	end := start + pagination.Limit
	if end > len(children) {
		end = len(children)
	}
	page := children[start:end]

	return ctx.JSON(http.StatusOK, svc.NewListResponse(page, total, pagination.Page, pagination.Limit))
}

// SSPDetail godoc

// @Summary		Per-SSP status for a control node
// @Description	Returns, for a control node, one row per System Security Plan: whether the control is in that plan's profile and its rolled-up posture, evidence status and declared implementation status there. Powers the drawer's plan-by-plan table. Only control keys (control:<catalogId>/<controlId>) are supported; other node kinds return 400.
// @Tags			Lineage
// @Produce		json
// @Param			key			path		string	true	"URL-encoded control node key"
// @Param			componentId	query		string	false	"Scope evidence to a system component"
// @Success		200			{object}	svc.ListResponse[LineageSSPRow]
// @Failure		400			{object}	api.Error
// @Failure		404			{object}	api.Error
// @Failure		500			{object}	api.Error
// @Security		OAuth2Password
// @Router			/lineage/nodes/{key}/ssps [get]
func (h *LineageHandler) SSPDetail(ctx echo.Context) error {
	// This table is inherently multi-SSP, so it ignores any sspId scope and always
	// walks every plan; componentId still narrows the evidence.
	_, componentID, err := parseScope(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	kind, catalogID, subID, err := parseNodeKey(ctx.Param("key"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if kind != "control" {
		return ctx.JSON(http.StatusBadRequest, api.NewError(errors.New("per-SSP detail is only available for control nodes")))
	}
	ref := relational.ControlRef{CatalogID: catalogID, ControlID: subID}

	engine, err := h.buildEngine(nil, componentID)
	if err != nil {
		h.sugar.Errorw("failed to build lineage engine", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if _, ok := engine.controlCatalogType[ref]; !ok {
		return ctx.JSON(http.StatusNotFound, api.NewError(errors.New("control not found")))
	}

	rows := make([]LineageSSPRow, 0, len(engine.allSSPIDs))
	for _, sspID := range engine.allSSPIDs {
		a := engine.assessSSP(ref, sspID, engine.profileControlsBySSP[sspID])
		rows = append(rows, LineageSSPRow{
			SSPID:                sspID.String(),
			SSPTitle:             engine.sspTitles[sspID],
			InProfile:            a.inScope,
			Posture:              a.posture,
			EvidenceStatus:       a.evidence,
			ImplementationStatus: a.impl,
			Leverage:             a.leverage,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SSPTitle == rows[j].SSPTitle {
			return rows[i].SSPID < rows[j].SSPID
		}
		return rows[i].SSPTitle < rows[j].SSPTitle
	})

	limit := len(rows)
	if limit < 1 {
		limit = 1
	}
	return ctx.JSON(http.StatusOK, svc.NewListResponse(rows, int64(len(rows)), 1, limit))
}

// ── Engine ─────────────────────────────────────────────────────────────────────

type catalogInfo struct {
	ctype  string
	title  string
	active bool
}

type groupMeta struct {
	ID    string
	Title string
}

type riskEntry struct {
	riskID uuid.UUID
	status string
	score  int
}

// lineageEngine holds everything loaded once per request to compute rollups
// without per-node N+1 queries.
type lineageEngine struct {
	db          *gorm.DB
	sspID       *uuid.UUID
	componentID *uuid.UUID

	graph *relational.ControlLinkGraph

	catalogs           map[uuid.UUID]catalogInfo
	controlTitle       map[relational.ControlRef]string
	controlStatement   map[relational.ControlRef]string
	controlCatalogType map[relational.ControlRef]string
	standardCatalogs   map[uuid.UUID]struct{}

	// catalogAllControls is the catalog's metric-rollup seed set: every control that
	// renders as a tree node (top-level + group-held). Sub-controls (enhancements
	// parented to another control) are excluded — they have no node, so counting them
	// would break the "parent totals == sum of visible children" invariant.
	catalogAllControls map[uuid.UUID][]relational.ControlRef
	catalogTopControls map[uuid.UUID][]relational.ControlRef
	catalogTopGroups   map[uuid.UUID][]groupMeta
	// groupControls is a group's FULL subtree of controls (self + descendant
	// groups), used for metric rollups. groupChildGroups / groupDirectControls are
	// the DIRECT children that expanding the group renders as its tree nodes.
	groupControls       map[string][]relational.ControlRef
	groupChildGroups    map[string][]groupMeta
	groupDirectControls map[string][]relational.ControlRef
	groupTitle          map[string]string

	// rollup inputs
	filtersByControl map[relational.ControlRef][]uuid.UUID
	controlStatus    map[relational.ControlRef]string
	risksByControl   map[relational.ControlRef][]riskEntry

	// Per-filter data kept for per-SSP evidence recomputation in the global view:
	// which SSP a filter is scoped to (nil = global filter, applies to every SSP)
	// and the latest-stream indices it matched (evaluated once in loadCompliance).
	filterSSP     map[uuid.UUID]*uuid.UUID
	filterMatched map[uuid.UUID][]int

	// Implementation status, per SSP, keyed by UPPER(controlID) -> uniform state
	// ("" when undeclared/mixed). Mirrors the controls page's strict-uniform
	// collapse over a control's by-components. Loaded for the selected SSP, or for
	// every SSP in the global view. Keyed by control-id only because an
	// implemented-requirement carries no catalog id (as elsewhere in the codebase).
	implStatusBySSP map[uuid.UUID]map[string]string

	// Cross-SSP leverage aggregates keyed by (SSP, UPPER(controlID)) — the inherited
	// credit, worst status, live satisfaction and responsibility counts per control.
	// Loaded once per engine build: single-SSP scope keys only the selected SSP;
	// global scope keys every downstream SSP. Keyed by control-id only, the same
	// precedent as implStatusBySSP.
	leverage map[leverage.ControlKey]leverage.ControlAggregate

	// Global multi-SSP scope (loaded only when sspID is nil): the full SSP list, each
	// SSP's title, and each SSP's resolved profile controls (scopeKey set), for the
	// cross-SSP breakdown on control nodes and the per-SSP drawer table.
	allSSPIDs            []uuid.UUID
	sspTitles            map[uuid.UUID]string
	profileControlsBySSP map[uuid.UUID]map[string]struct{}

	// closureCache memoizes a control's evidence closure (itself + everything that
	// implements it) so posture can roll up through control-links like compliance
	// and risk do, without re-walking the graph per SSP.
	closureCache map[relational.ControlRef][]relational.ControlRef
	// assessCache memoizes assessSSP per (control, SSP). The global /roots view sums
	// a control's posture across every SSP for every ancestor node it rolls into, so
	// the same (control, SSP) assessment (and its closureStreamsForSSP walk) is asked
	// for many times over. The membership arg is a deterministic function of sspID
	// within one engine build, so keying on (ref, sspID) alone is sound.
	assessCache map[assessKey]sspAssessment
	// latestStreams holds every latest-per-stream evidence (loaded once); the
	// per-control indices into it are the control's own compliance evidence.
	latestStreams            []relational.LatestEvidenceStream
	evidenceStreamsByControl map[relational.ControlRef][]int

	// SSP scope: standard controls resolved by the SSP's profiles.
	profileControlSet map[string]struct{}
}

func (h *LineageHandler) buildEngine(sspID, componentID *uuid.UUID) (*lineageEngine, error) {
	e := &lineageEngine{
		db:                       h.db,
		sspID:                    sspID,
		componentID:              componentID,
		catalogs:                 map[uuid.UUID]catalogInfo{},
		controlTitle:             map[relational.ControlRef]string{},
		controlStatement:         map[relational.ControlRef]string{},
		controlCatalogType:       map[relational.ControlRef]string{},
		standardCatalogs:         map[uuid.UUID]struct{}{},
		catalogAllControls:       map[uuid.UUID][]relational.ControlRef{},
		catalogTopControls:       map[uuid.UUID][]relational.ControlRef{},
		catalogTopGroups:         map[uuid.UUID][]groupMeta{},
		groupControls:            map[string][]relational.ControlRef{},
		groupChildGroups:         map[string][]groupMeta{},
		groupDirectControls:      map[string][]relational.ControlRef{},
		groupTitle:               map[string]string{},
		filtersByControl:         map[relational.ControlRef][]uuid.UUID{},
		controlStatus:            map[relational.ControlRef]string{},
		risksByControl:           map[relational.ControlRef][]riskEntry{},
		evidenceStreamsByControl: map[relational.ControlRef][]int{},
		profileControlSet:        map[string]struct{}{},
		filterSSP:                map[uuid.UUID]*uuid.UUID{},
		filterMatched:            map[uuid.UUID][]int{},
		implStatusBySSP:          map[uuid.UUID]map[string]string{},
		sspTitles:                map[uuid.UUID]string{},
		profileControlsBySSP:     map[uuid.UUID]map[string]struct{}{},
		closureCache:             map[relational.ControlRef][]relational.ControlRef{},
		assessCache:              map[assessKey]sspAssessment{},
		leverage:                 map[leverage.ControlKey]leverage.ControlAggregate{},
	}

	if err := e.loadCatalogs(h.db); err != nil {
		return nil, err
	}
	if err := e.loadEdges(h.db); err != nil {
		return nil, err
	}
	if err := e.loadCompliance(h.db); err != nil {
		return nil, err
	}
	if err := e.loadRisks(h.db); err != nil {
		return nil, err
	}
	if err := e.loadLeverage(h.db); err != nil {
		return nil, err
	}
	if sspID != nil {
		if err := e.loadProfileScope(h.db, *sspID); err != nil {
			return nil, err
		}
		if err := e.loadImplementationStatuses(h.db, []uuid.UUID{*sspID}); err != nil {
			return nil, err
		}
		if err := e.loadSSPTitle(h.db, *sspID); err != nil {
			return nil, err
		}
	} else {
		if err := e.loadGlobalSSPScope(h.db); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (e *lineageEngine) loadCatalogs(db *gorm.DB) error {
	var catalogs []relational.Catalog
	// Only Metadata/Controls/Groups: these has-many associations filter by
	// catalog_id, so every row belongs to its catalog. The nested polymorphic
	// preloads (Groups.Groups, Groups.Controls) must NOT be used — their join key
	// is an unscoped parent_id string, so a catalog imported more than once matches
	// sibling rows across catalogs and duplicates the tree. The hierarchy is rebuilt
	// below from these flat, catalog-scoped lists via parent_id.
	if err := db.
		Preload("Metadata").
		Preload("Controls").
		Preload("Groups").
		Find(&catalogs).Error; err != nil {
		return err
	}

	for i := range catalogs {
		cat := catalogs[i]
		if cat.ID == nil {
			continue
		}
		catID := *cat.ID
		ctype := cat.CatalogType
		if ctype == "" {
			ctype = relational.CatalogTypeStandard
		}
		// A nil Active (never written / legacy row) is treated as active, matching
		// the column's default:true. Inactive catalogs are still loaded fully so
		// their controls remain reachable as control-link targets/sources; only the
		// /roots listing filters them out.
		active := cat.Active == nil || *cat.Active
		e.catalogs[catID] = catalogInfo{ctype: ctype, title: cat.Metadata.Title, active: active}
		if relational.IsOperationalCatalogType(ctype) {
			e.standardCatalogs[catID] = struct{}{}
		}

		register := func(ref relational.ControlRef, c relational.Control) {
			e.controlTitle[ref] = c.Title
			e.controlCatalogType[ref] = ctype
			if s := controlStatement(c); s != "" {
				e.controlStatement[ref] = s
			}
		}

		// Group hierarchy, rebuilt from this catalog's flat group list: a group whose
		// parent_id is nil is a catalog child; otherwise it is a direct sub-group of
		// its parent. parent_id is only trustworthy WITHIN one catalog, which is
		// exactly the scope of cat.Groups.
		groupIDs := make(map[string]struct{}, len(cat.Groups))
		for _, g := range cat.Groups {
			groupIDs[g.ID] = struct{}{}
		}
		for _, g := range cat.Groups {
			gkey := groupKey(catID, g.ID)
			e.groupTitle[gkey] = g.Title
			if g.ParentID == nil {
				e.catalogTopGroups[catID] = append(e.catalogTopGroups[catID], groupMeta{ID: g.ID, Title: g.Title})
				continue
			}
			pkey := groupKey(catID, *g.ParentID)
			e.groupChildGroups[pkey] = append(e.groupChildGroups[pkey], groupMeta{ID: g.ID, Title: g.Title})
		}

		// Classify and register every control. A control's parent is a group (direct
		// group control), another control (a sub-control / enhancement) or the catalog
		// itself (top-level control). Every control is registered so it stays reachable
		// as a control-link endpoint, but only controls that render as a tree node —
		// top-level and group-held — seed the rollups. A sub-control (parent is another
		// control) has no node of its own and is counted in no group beneath the
		// catalog, so counting it in catalogAllControls would inflate the catalog's
		// totals past the sum of its visible children. It is therefore excluded from
		// the rollup seeds until enhancements are rendered under their parent control.
		rollupControls := make([]relational.ControlRef, 0, len(cat.Controls))
		topControls := []relational.ControlRef{}
		for _, ctl := range cat.Controls {
			ref := relational.ControlRef{CatalogID: catID, ControlID: ctl.ID}
			register(ref, ctl)
			if ctl.ParentID == nil {
				topControls = append(topControls, ref)
				rollupControls = append(rollupControls, ref)
			} else if _, isGroup := groupIDs[*ctl.ParentID]; isGroup {
				pkey := groupKey(catID, *ctl.ParentID)
				e.groupDirectControls[pkey] = append(e.groupDirectControls[pkey], ref)
				rollupControls = append(rollupControls, ref)
			}
		}
		e.catalogTopControls[catID] = topControls
		e.catalogAllControls[catID] = rollupControls

		// A group's full subtree = its direct controls plus every descendant group's,
		// walked over the direct-child maps (depth-independent, cycle-tolerant). Used
		// for the group node's metric rollup.
		var subtree func(gkey string, seen map[string]struct{}) []relational.ControlRef
		subtree = func(gkey string, seen map[string]struct{}) []relational.ControlRef {
			if cached, ok := e.groupControls[gkey]; ok {
				return cached
			}
			if _, cycle := seen[gkey]; cycle {
				return nil
			}
			seen[gkey] = struct{}{}
			out := append([]relational.ControlRef{}, e.groupDirectControls[gkey]...)
			for _, sub := range e.groupChildGroups[gkey] {
				out = append(out, subtree(groupKey(catID, sub.ID), seen)...)
			}
			e.groupControls[gkey] = out
			return out
		}
		for _, g := range cat.Groups {
			subtree(groupKey(catID, g.ID), map[string]struct{}{})
		}
	}
	return nil
}

func (e *lineageEngine) loadEdges(db *gorm.DB) error {
	edges := []relational.ControlLink{}
	if err := db.Find(&edges).Error; err != nil {
		return err
	}
	e.graph = relational.NewControlLinkGraph(edges)
	return nil
}

func (e *lineageEngine) loadCompliance(db *gorm.DB) error {
	var filters []relational.Filter
	q := db.Preload("Controls")
	if e.sspID != nil {
		q = q.Where("ssp_id IS NULL OR ssp_id = ?", *e.sspID)
	}
	if err := q.Find(&filters).Error; err != nil {
		return err
	}

	scopeByFilter := map[uuid.UUID]*labelfilter.Scope{}
	for i := range filters {
		f := filters[i]
		if f.ID == nil {
			continue
		}
		scopeByFilter[*f.ID] = f.Filter.Data().Scope
		// Record which SSP each filter is scoped to (nil = global filter, counts for
		// every SSP), so the global view can recompute evidence per SSP in memory.
		e.filterSSP[*f.ID] = f.SSPID
		for _, c := range f.Controls {
			ref := relational.ControlRef{CatalogID: c.CatalogID, ControlID: c.ID}
			e.filtersByControl[ref] = append(e.filtersByControl[ref], *f.ID)
		}
	}

	// Load the latest evidence per stream once, then evaluate filters in memory.
	streams, err := relational.LoadLatestEvidenceStreams(db, e.componentID)
	if err != nil {
		return err
	}
	e.latestStreams = streams

	// Each filter's matching stream indices (evaluated once).
	for id, scope := range scopeByFilter {
		for i := range streams {
			m, matchErr := labelfilter.MatchLabels(scope, streams[i].Labels)
			if matchErr != nil {
				return matchErr
			}
			if m {
				e.filterMatched[id] = append(e.filterMatched[id], i)
			}
		}
	}

	// Per control: the distinct latest streams matching any of its filters (the
	// control's own compliance evidence), plus the derived compliance status. In
	// single-SSP scope the loaded filters are already SSP-scoped, so controlStatus
	// is the selected SSP's evidence status.
	for ref, ids := range e.filtersByControl {
		e.evidenceStreamsByControl[ref] = e.mergeFilterStreams(ids)
		e.controlStatus[ref] = e.statusFromStreams(e.evidenceStreamsByControl[ref])
	}
	return nil
}

// mergeFilterStreams returns the distinct latest-stream indices matched by any of
// the given filter ids, preserving first-seen order.
func (e *lineageEngine) mergeFilterStreams(filterIDs []uuid.UUID) []int {
	seen := map[int]struct{}{}
	matched := []int{}
	for _, id := range filterIDs {
		for _, si := range e.filterMatched[id] {
			if _, dup := seen[si]; !dup {
				seen[si] = struct{}{}
				matched = append(matched, si)
			}
		}
	}
	return matched
}

// statusFromStreams collapses a control's matching latest-evidence streams into
// one status: any not-satisfied wins; else any satisfied; else unknown.
func (e *lineageEngine) statusFromStreams(indices []int) string {
	hasSatisfied := false
	for _, i := range indices {
		switch strings.ToLower(strings.TrimSpace(e.latestStreams[i].State)) {
		case relational.EvidenceStatusNotSatisfied:
			return relational.EvidenceStatusNotSatisfied
		case relational.EvidenceStatusSatisfied:
			hasSatisfied = true
		}
	}
	if hasSatisfied {
		return relational.EvidenceStatusSatisfied
	}
	return "unknown"
}

type riskScanRow struct {
	CatalogID  uuid.UUID `gorm:"column:catalog_id"`
	ControlID  string    `gorm:"column:control_id"`
	RiskID     uuid.UUID `gorm:"column:risk_id"`
	Status     string    `gorm:"column:status"`
	Likelihood *string   `gorm:"column:likelihood"`
	Impact     *string   `gorm:"column:impact"`
}

func (e *lineageEngine) loadRisks(db *gorm.DB) error {
	q := db.Table("risk_control_links rcl").
		Select("rcl.catalog_id, rcl.control_id, r.id as risk_id, r.status, r.likelihood, r.impact").
		Joins("JOIN risk_register_risks r ON r.id = rcl.risk_id").
		// Closed risks are dropped from the lineage entirely — they only clutter the
		// tree/graph. Remediated risks stay (they already contribute nothing to the
		// heat sums, but remain visible as nodes).
		Where("r.status != ?", string(riskrel.RiskStatusClosed))
	if e.sspID != nil {
		q = q.Where("r.ssp_id = ?", *e.sspID)
	}
	if e.componentID != nil {
		q = q.Joins("JOIN risk_component_links rcomp ON rcomp.risk_id = r.id").
			Where("rcomp.component_id = ?", *e.componentID)
	}

	rows := []riskScanRow{}
	if err := q.Scan(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		score, _ := riskrel.NumericalRiskScore(row.Likelihood, row.Impact)
		ref := relational.ControlRef{CatalogID: row.CatalogID, ControlID: row.ControlID}
		e.risksByControl[ref] = append(e.risksByControl[ref], riskEntry{
			riskID: row.RiskID,
			status: row.Status,
			score:  score,
		})
	}
	return nil
}

func (e *lineageEngine) loadProfileScope(db *gorm.DB, sspID uuid.UUID) error {
	type profileControlRow struct {
		ControlCatalogID uuid.UUID `gorm:"column:control_catalog_id"`
		ControlID        string    `gorm:"column:control_id"`
	}
	rows := []profileControlRow{}
	if err := db.
		Table("profile_controls").
		Select("profile_controls.control_catalog_id, profile_controls.control_id").
		Joins("JOIN ssp_profiles ON ssp_profiles.profile_id = profile_controls.profile_id").
		Where("ssp_profiles.system_security_plan_id = ?", sspID).
		Scan(&rows).Error; err != nil {
		return err
	}
	for _, row := range rows {
		e.profileControlSet[scopeKey(relational.ControlRef{CatalogID: row.ControlCatalogID, ControlID: row.ControlID})] = struct{}{}
	}
	return nil
}

// loadImplementationStatuses populates implStatusBySSP for the given SSPs with
// each control's uniform implementation status. It reads every by-component
// attached to the SSP's implemented-requirements (both requirement-level and
// statement-level) and collapses them per control-id with strict uniformity — a
// control is only assigned a status when EVERY by-component agrees on the same
// non-empty state, exactly like the controls page's uniformImplementationStatusCue.
func (e *lineageEngine) loadImplementationStatuses(db *gorm.DB, sspIDs []uuid.UUID) error {
	for _, id := range sspIDs {
		if _, ok := e.implStatusBySSP[id]; !ok {
			e.implStatusBySSP[id] = map[string]string{}
		}
	}
	if len(sspIDs) == 0 {
		return nil
	}

	type statusRow struct {
		SSPID     uuid.UUID `gorm:"column:ssp_id"`
		ControlID string    `gorm:"column:control_id"`
		State     *string   `gorm:"column:state"`
	}
	// Requirement-level and statement-level by-components both carry an
	// implementation status; UNION ALL them so a control's full set is collapsed
	// together. Postgres-first (matches the rest of the engine's raw queries).
	query := `
		SELECT ci.system_security_plan_id AS ssp_id, ir.control_id AS control_id,
		       bc.implementation_status->>'state' AS state
		FROM implemented_requirements ir
		JOIN control_implementations ci ON ci.id = ir.control_implementation_id
		JOIN by_components bc ON bc.parent_id = ir.id AND bc.parent_type = 'implemented_requirements'
		WHERE ci.system_security_plan_id IN ?
		UNION ALL
		SELECT ci.system_security_plan_id AS ssp_id, ir.control_id AS control_id,
		       bc.implementation_status->>'state' AS state
		FROM implemented_requirements ir
		JOIN control_implementations ci ON ci.id = ir.control_implementation_id
		JOIN statements st ON st.implemented_requirement_id = ir.id
		JOIN by_components bc ON bc.parent_id = st.id AND bc.parent_type = 'statements'
		WHERE ci.system_security_plan_id IN ?`
	rows := []statusRow{}
	if err := db.Raw(query, sspIDs, sspIDs).Scan(&rows).Error; err != nil {
		return err
	}

	// Gather each control's states, then collapse. A control with an
	// implemented-requirement but no by-components never appears here, so it stays
	// undeclared ("") — the "in profile, no status" case.
	statesByControl := map[uuid.UUID]map[string][]string{}
	for _, r := range rows {
		key := strings.ToUpper(strings.TrimSpace(r.ControlID))
		if statesByControl[r.SSPID] == nil {
			statesByControl[r.SSPID] = map[string][]string{}
		}
		state := ""
		if r.State != nil {
			state = *r.State
		}
		statesByControl[r.SSPID][key] = append(statesByControl[r.SSPID][key], state)
	}
	for sspID, byControl := range statesByControl {
		for controlKey, states := range byControl {
			if s := collapseUniformStatus(states); s != "" {
				e.implStatusBySSP[sspID][controlKey] = s
			}
		}
	}
	return nil
}

// loadSSPTitle resolves the single scoped SSP's title into sspTitles, so risk
// nodes can carry it the same way they do in the global (no sspId) view.
func (e *lineageEngine) loadSSPTitle(db *gorm.DB, sspID uuid.UUID) error {
	var ssp relational.SystemSecurityPlan
	if err := db.Preload("Metadata").First(&ssp, "id = ?", sspID).Error; err != nil {
		return err
	}
	e.sspTitles[sspID] = ssp.Metadata.Title
	return nil
}

// loadGlobalSSPScope loads the full SSP list, each SSP's resolved profile controls
// and every SSP's implementation statuses, so control nodes can report a cross-SSP
// posture breakdown in the global (no sspId) view.
func (e *lineageEngine) loadGlobalSSPScope(db *gorm.DB) error {
	var ssps []relational.SystemSecurityPlan
	if err := db.Preload("Metadata").Find(&ssps).Error; err != nil {
		return err
	}
	for i := range ssps {
		if ssps[i].ID == nil {
			continue
		}
		id := *ssps[i].ID
		e.allSSPIDs = append(e.allSSPIDs, id)
		e.sspTitles[id] = ssps[i].Metadata.Title
		e.profileControlsBySSP[id] = map[string]struct{}{}
	}
	if len(e.allSSPIDs) == 0 {
		return nil
	}

	type membershipRow struct {
		SSPID     uuid.UUID `gorm:"column:ssp_id"`
		CatalogID uuid.UUID `gorm:"column:control_catalog_id"`
		ControlID string    `gorm:"column:control_id"`
	}
	rows := []membershipRow{}
	if err := db.
		Table("ssp_profiles").
		Select("ssp_profiles.system_security_plan_id AS ssp_id, profile_controls.control_catalog_id, profile_controls.control_id").
		Joins("JOIN profile_controls ON profile_controls.profile_id = ssp_profiles.profile_id").
		Scan(&rows).Error; err != nil {
		return err
	}
	for _, r := range rows {
		set, ok := e.profileControlsBySSP[r.SSPID]
		if !ok {
			// An SSP referenced by ssp_profiles but not returned by the list query
			// (e.g. soft-deleted) is ignored for the breakdown.
			continue
		}
		set[scopeKey(relational.ControlRef{CatalogID: r.CatalogID, ControlID: r.ControlID})] = struct{}{}
	}

	return e.loadImplementationStatuses(db, e.allSSPIDs)
}

// loadLeverage summarizes every leverage link in scope (single SSP when e.sspID is
// set, all downstream SSPs otherwise) and aggregates it per (SSP, control-id). Run
// once per engine build; Summarize does ~7 bulk queries regardless of link count.
func (e *lineageEngine) loadLeverage(db *gorm.DB) error {
	summaries, err := leverage.Summarize(db, e.sspID)
	if err != nil {
		return err
	}
	e.leverage = leverage.AggregateByControl(summaries)
	return nil
}

// leverageAgg returns the leverage aggregate for a (control, SSP) cell, matched by
// UPPER-folded control-id only (no catalog id — the established leverage precedent).
// ok is false when the SSP holds no leverage link for that control-id.
func (e *lineageEngine) leverageAgg(ref relational.ControlRef, sspID uuid.UUID) (leverage.ControlAggregate, bool) {
	agg, ok := e.leverage[leverage.ControlKey{SSPID: sspID, ControlID: leverage.NormalizeControlID(ref.ControlID)}]
	return agg, ok
}

// derivePosture applies the posture ladder for one control in one SSP: scope, then
// decisive evidence, then — only when evidence is inconclusive — machine-verified
// inherited credit, then declared implementation status. Inherited sits above
// not-applicable/planned: both are non-problem rungs, but the leverage rung is
// machine-verified (drift monitoring, re-attest) and carries more information. Evidence
// always wins over inherited credit in both directions.
func derivePosture(inScope bool, evidenceStatus, implStatus string, inheritedCredit bool) string {
	if !inScope {
		return PostureOutOfScope
	}
	switch evidenceStatus {
	case relational.EvidenceStatusNotSatisfied:
		return PostureNotSatisfied
	case relational.EvidenceStatusSatisfied:
		return PostureSatisfied
	}
	if inheritedCredit {
		return PostureInherited
	}
	switch implStatus {
	case string(relational.ImplementationStatusNotApplicable):
		return PostureNotApplicable
	case string(relational.ImplementationStatusPlanned):
		return PosturePlanned
	}
	return PostureAttention
}

// closureOf returns a control's evidence closure (itself plus every control that
// transitively implements it), memoized. This is the same closure compliance and
// risk roll up over, so an abstract standard control inherits the coverage of the
// concrete policy/operational controls linked to implement it.
func (e *lineageEngine) closureOf(ref relational.ControlRef) []relational.ControlRef {
	if cached, ok := e.closureCache[ref]; ok {
		return cached
	}
	set := e.graph.EvidenceClosure(ref)
	out := make([]relational.ControlRef, 0, len(set))
	for m := range set {
		out = append(out, m)
	}
	e.closureCache[ref] = out
	return out
}

// sspAssessment is a control's rolled-up standing in one SSP.
type sspAssessment struct {
	posture  string
	inScope  bool
	evidence string // satisfied / not-satisfied / unknown
	impl     string // uniform declared status across in-scope implementers, or ""
	// leverage is the badge summary for this (control, SSP) cell, non-nil whenever the
	// SSP holds at least one leverage link for the control-id (credit or not).
	leverage *LineageLeverageSummary
}

// assessKey memoizes assessSSP. Comparable (ControlRef + uuid.UUID are both
// comparable), so it keys assessCache directly.
type assessKey struct {
	ref   relational.ControlRef
	sspID uuid.UUID
}

// assessSSP rolls a control's posture up through its implements-closure for one
// SSP. A control is in scope when it — or ANY operational control implementing it
// — sits in the SSP's profile; its evidence is the closure's combined evidence for
// that SSP; its declared status is the strict-uniform status of the in-scope
// implementers. This keeps posture consistent with the compliance/risk rollups:
// a standard control implemented indirectly (internal control -> policy ->
// standard) inherits that SSP's coverage instead of reading as out-of-scope.
func (e *lineageEngine) assessSSP(ref relational.ControlRef, sspID uuid.UUID, membership map[string]struct{}) sspAssessment {
	key := assessKey{ref: ref, sspID: sspID}
	if cached, ok := e.assessCache[key]; ok {
		return cached
	}
	closure := e.closureOf(ref)

	// In scope when the control — or anything implementing it — sits in the SSP's
	// profile, regardless of catalog type: a policy carried by a profile is assessed
	// like a control, and a policy/standard inherits its implementers' membership.
	inScope := false
	implStates := []string{}
	for _, m := range closure {
		if _, ok := membership[scopeKey(m)]; !ok {
			continue
		}
		inScope = true
		implStates = append(implStates, e.implStatusBySSP[sspID][strings.ToUpper(m.ControlID)])
	}

	evidence := e.statusFromStreams(e.closureStreamsForSSP(closure, sspID))
	impl := collapseUniformStatus(implStates)

	// Inherited credit is checked on ref itself, not the implements-closure: leverage
	// links are recorded against the concrete control-id, and parents pick inherited
	// leaves up through the postureCountsFor / sspBreakdownForSet leaf tallies. Evidence
	// still wins (derivePosture consults credit only when evidence is inconclusive).
	agg, hasLeverage := e.leverageAgg(ref, sspID)
	a := sspAssessment{
		posture:  derivePosture(inScope, evidence, impl, hasLeverage && agg.Credit),
		inScope:  inScope,
		evidence: evidence,
		impl:     impl,
	}
	if hasLeverage {
		a.leverage = &LineageLeverageSummary{
			Links:                 agg.Links,
			Status:                string(agg.Status),
			Satisfaction:          string(agg.Satisfaction),
			OutstandingCount:      agg.OutstandingCount,
			TotalResponsibilities: agg.TotalResponsibilities,
		}
	}
	e.assessCache[key] = a
	return a
}

// inAnySSPProfile reports whether a control is directly resolved by at least one
// SSP's profile — in single-SSP scope that is the selected SSP, globally it is any
// SSP. Used to suppress the "unmapped" orphan warning for a control that, while
// unlinked in the lineage graph, is still tracked by an SSP.
func (e *lineageEngine) inAnySSPProfile(ref relational.ControlRef) bool {
	key := scopeKey(ref)
	if e.sspID != nil {
		_, ok := e.profileControlSet[key]
		return ok
	}
	for _, set := range e.profileControlsBySSP {
		if _, ok := set[key]; ok {
			return true
		}
	}
	return false
}

// closureStreamsForSSP unions the latest-stream indices matched by every filter of
// every closure member that applies to the SSP (global filters, or ones scoped to
// that SSP).
func (e *lineageEngine) closureStreamsForSSP(closure []relational.ControlRef, sspID uuid.UUID) []int {
	seen := map[int]struct{}{}
	streams := []int{}
	for _, m := range closure {
		for _, fid := range e.filtersByControl[m] {
			if s := e.filterSSP[fid]; s != nil && *s != sspID {
				continue
			}
			for _, si := range e.filterMatched[fid] {
				if _, dup := seen[si]; !dup {
					seen[si] = struct{}{}
					streams = append(streams, si)
				}
			}
		}
	}
	return streams
}

// controlSSPStatus builds the full posture overlay for an operational control in
// the selected SSP, rolled up through its implements-closure.
func (e *lineageEngine) controlSSPStatus(ref relational.ControlRef) LineageSSPStatus {
	a := e.assessSSP(ref, *e.sspID, e.profileControlSet)
	return LineageSSPStatus{
		Posture:              a.posture,
		InProfile:            a.inScope,
		EvidenceStatus:       a.evidence,
		ImplementationStatus: a.impl,
		Leverage:             a.leverage,
	}
}

// postureCountsFor tallies the postures of the given seeds' distinct operational
// controls in the selected SSP. Returns nil when no seed is an operational control
// (posture is undefined for policy/procedure controls, which are never in a profile).
func (e *lineageEngine) postureCountsFor(seeds []relational.ControlRef) *LineagePostureCounts {
	if e.sspID == nil {
		return nil
	}
	counts := &LineagePostureCounts{}
	seen := map[relational.ControlRef]struct{}{}
	any := false
	// Sum the descendant leaf controls up the tree — the single-SSP analogue of the
	// global sspBreakdown. Walk each seed's evidence closure, skip abstract
	// pass-throughs (the same controls the compliance rollup skips), and bucket each
	// leaf's posture for the selected SSP, including out-of-scope leaves the SSP's
	// profile doesn't carry. So a parent's bar equals the sum of its children's.
	for _, seed := range seeds {
		for _, ref := range e.closureOf(seed) {
			if _, dup := seen[ref]; dup {
				continue
			}
			seen[ref] = struct{}{}
			if !e.countsInCompliance(ref) {
				continue
			}
			any = true
			switch e.assessSSP(ref, *e.sspID, e.profileControlSet).posture {
			case PostureSatisfied:
				counts.Satisfied++
			case PostureNotSatisfied:
				counts.NotSatisfied++
			case PostureInherited:
				counts.Inherited++
			case PostureNotApplicable:
				counts.NotApplicable++
			case PosturePlanned:
				counts.Planned++
			case PostureOutOfScope:
				counts.OutOfScope++
			default:
				counts.Attention++
			}
		}
	}
	if !any {
		return nil
	}
	return counts
}

// controlSSPBreakdown tallies an operational control's posture across every SSP in
// the global view. It is the sum, over every counting control in the set (the same
// controls the compliance rollup counts — abstract pass-throughs excluded) and
// every SSP, of that control's posture. So a structural or abstract node's bar is
// the aggregate of all the leaf controls beneath it, one posture per (control,
// SSP) cell; a parent's bar equals the sum of its children's. Returns nil when
// there are no SSPs or no counting controls (single-SSP scope loads no SSP list,
// so this is naturally nil there).
func (e *lineageEngine) sspBreakdownForSet(set map[relational.ControlRef]struct{}) *LineageSSPBreakdown {
	if len(e.allSSPIDs) == 0 {
		return nil
	}
	b := &LineageSSPBreakdown{TotalSSPs: len(e.allSSPIDs)}
	counted := false
	for ref := range set {
		if !e.countsInCompliance(ref) {
			continue
		}
		counted = true
		for _, sspID := range e.allSSPIDs {
			switch e.assessSSP(ref, sspID, e.profileControlsBySSP[sspID]).posture {
			case PostureSatisfied:
				b.Satisfied++
			case PostureNotSatisfied:
				b.NotSatisfied++
			case PostureInherited:
				b.Inherited++
			case PostureNotApplicable:
				b.NotApplicable++
			case PosturePlanned:
				b.Planned++
			case PostureOutOfScope:
				b.OutOfScope++
			default:
				b.Attention++
			}
		}
	}
	if !counted {
		return nil
	}
	return b
}

// collapseUniformStatus reduces a control's by-component states to a single
// implementation status: the shared state when every by-component agrees on the
// same non-empty value, else "" (undeclared or mixed). Strictly mirrors the UI's
// uniformImplementationStatusCue.
func collapseUniformStatus(states []string) string {
	uniform := ""
	for i, s := range states {
		s = strings.ToLower(strings.TrimSpace(s))
		if i == 0 {
			uniform = s
			continue
		}
		if s != uniform {
			return ""
		}
	}
	return uniform
}

// inScope reports whether a control contributes to the current metric scope.
// Global scope includes everything; SSP scope restricts standard controls to the
// SSP's resolved profile controls while always including policy/procedure controls.
func (e *lineageEngine) inScope(ref relational.ControlRef) bool {
	if e.sspID == nil {
		return true
	}
	switch e.controlCatalogType[ref] {
	case relational.CatalogTypePolicy, relational.CatalogTypeProcedure:
		return true
	default:
		_, ok := e.profileControlSet[scopeKey(ref)]
		return ok
	}
}

// evidenceSet returns the distinct in-scope controls whose evidence/risk rolls up
// into the given seed controls: each seed plus its implements-closure.
func (e *lineageEngine) evidenceSet(seeds []relational.ControlRef) map[relational.ControlRef]struct{} {
	set := map[relational.ControlRef]struct{}{}
	for _, s := range seeds {
		for m := range e.graph.EvidenceClosure(s) {
			if e.inScope(m) {
				set[m] = struct{}{}
			}
		}
	}
	return set
}

// countsInCompliance reports whether a control contributes its own status to a
// compliance rollup. A control that has implementing control-links (something
// implements it) and carries no decisive evidence of its own is an abstract
// pass-through: its compliance is fully delegated to its implementers, so
// counting it would just add a spurious "unknown" to the total. Such a control is
// skipped and represented by its implementers instead. Leaf controls, and linked
// controls that DO have their own satisfied/not-satisfied evidence, still count.
func (e *lineageEngine) countsInCompliance(ref relational.ControlRef) bool {
	if len(e.graph.ImplementsChildren(ref)) == 0 {
		return true
	}
	switch e.controlStatus[ref] {
	case relational.EvidenceStatusSatisfied, relational.EvidenceStatusNotSatisfied:
		return true
	default:
		return false
	}
}

// complianceFor builds the compliance pill. In the global view with SSPs it is
// derived from the per-(control, SSP) breakdown so a control's status in one SSP
// doesn't overwrite its status in another (a control failing in one plan and
// planned/not-applicable in another shows as both, not collapsed to failing);
// out-of-scope cells don't count against compliance. Without a breakdown
// (single-SSP scope, or no SSPs at all) it counts each control once by its
// (SSP-scoped) evidence status, skipping abstract pass-through controls.
func (e *lineageEngine) complianceFor(set map[relational.ControlRef]struct{}, breakdown *LineageSSPBreakdown) LineageCompliance {
	if breakdown != nil {
		sat := breakdown.Satisfied
		not := breakdown.NotSatisfied
		inh := breakdown.Inherited
		// Attention/not-applicable/planned are the in-scope-but-not-proven cells.
		// Inherited is credited (compliant + assessed), not part of Unknown.
		unk := breakdown.Attention + breakdown.NotApplicable + breakdown.Planned
		total := sat + inh + not + unk
		return LineageCompliance{
			TotalControls:     total,
			Satisfied:         sat,
			NotSatisfied:      not,
			Unknown:           unk,
			Inherited:         inh,
			CompliancePercent: pct1(sat+inh, total),
			AssessedPercent:   pct1(sat+inh+not, total),
		}
	}

	total, sat, not, unk, inh := 0, 0, 0, 0, 0
	for ref := range set {
		if !e.countsInCompliance(ref) {
			continue
		}
		total++
		switch e.controlStatus[ref] {
		case relational.EvidenceStatusSatisfied:
			sat++
		case relational.EvidenceStatusNotSatisfied:
			not++
		default:
			// Evidence is inconclusive. In single-SSP scope, promote to inherited when
			// the control is in scope and its leverage links earn credit — the fallback
			// analogue of the breakdown's per-cell inherited posture. Global-with-no-SSPs
			// has no SSP to key leverage on, so this never fires there.
			if e.sspID != nil && e.inScope(ref) {
				if agg, ok := e.leverageAgg(ref, *e.sspID); ok && agg.Credit {
					inh++
					continue
				}
			}
			unk++
		}
	}
	return LineageCompliance{
		TotalControls:     total,
		Satisfied:         sat,
		NotSatisfied:      not,
		Unknown:           unk,
		Inherited:         inh,
		CompliancePercent: pct1(sat+inh, total),
		AssessedPercent:   pct1(sat+inh+not, total),
	}
}

func (e *lineageEngine) risk(set map[relational.ControlRef]struct{}) LineageRisk {
	entries := make([]riskEntry, 0)
	for ref := range set {
		entries = append(entries, e.risksByControl[ref]...)
	}
	return bucketRisks(entries)
}

func (e *lineageEngine) linkageFor(seeds []relational.ControlRef, isPolicyNode bool) LineageLinkage {
	seedSet := map[relational.ControlRef]struct{}{}
	for _, s := range seeds {
		seedSet[s] = struct{}{}
	}
	closure := map[relational.ControlRef]struct{}{}
	for _, s := range seeds {
		for m := range e.graph.StructuralClosure(s) {
			closure[m] = struct{}{}
		}
	}

	policies, procedures, operational := 0, 0, 0
	for m := range closure {
		if _, isSeed := seedSet[m]; isSeed {
			continue
		}
		switch e.controlCatalogType[m] {
		case relational.CatalogTypePolicy:
			policies++
		case relational.CatalogTypeProcedure:
			procedures++
		default:
			operational++
		}
	}

	anchored := false
	for _, s := range seeds {
		if e.graph.HasOutgoingImplements(s, e.standardCatalogs) {
			anchored = true
			break
		}
	}

	return LineageLinkage{
		Policies:            policies,
		Procedures:          procedures,
		OperationalControls: operational,
		Unanchored:          isPolicyNode && !anchored,
	}
}

func (e *lineageEngine) catalogNode(catID uuid.UUID) LineageNode {
	info := e.catalogs[catID]
	seeds := e.catalogAllControls[catID]
	set := e.evidenceSet(seeds)
	breakdown := e.sspBreakdownForSet(set)
	childCount := len(e.catalogTopGroups[catID]) + len(e.catalogTopControls[catID])
	return LineageNode{
		Key:           "catalog:" + catID.String(),
		NodeType:      catalogNodeType(info.ctype),
		CatalogID:     catID.String(),
		Title:         info.title,
		Compliance:    e.complianceFor(set, breakdown),
		Risk:          e.risk(set),
		Linkage:       e.linkageFor(seeds, info.ctype == relational.CatalogTypePolicy),
		PostureCounts: e.postureCountsFor(seeds),
		SSPBreakdown:  breakdown,
		HasChildren:   childCount > 0,
		ChildrenCount: childCount,
	}
}

func (e *lineageEngine) groupNode(catID uuid.UUID, groupID string) LineageNode {
	gkey := groupKey(catID, groupID)
	// Metrics roll up over the whole subtree; child count is the DIRECT children
	// (sub-groups + directly-held controls) that expanding this group renders.
	seeds := e.groupControls[gkey]
	set := e.evidenceSet(seeds)
	breakdown := e.sspBreakdownForSet(set)
	childCount := len(e.groupChildGroups[gkey]) + len(e.groupDirectControls[gkey])
	return LineageNode{
		Key:           "group:" + catID.String() + "/" + groupID,
		NodeType:      "group",
		CatalogID:     catID.String(),
		GroupID:       groupID,
		Title:         e.groupTitle[gkey],
		Compliance:    e.complianceFor(set, breakdown),
		Risk:          e.risk(set),
		Linkage:       e.linkageFor(seeds, false),
		PostureCounts: e.postureCountsFor(seeds),
		SSPBreakdown:  breakdown,
		HasChildren:   childCount > 0,
		ChildrenCount: childCount,
	}
}

func (e *lineageEngine) controlNode(ref relational.ControlRef) LineageNode {
	ctype := e.controlCatalogType[ref]
	set := e.evidenceSet([]relational.ControlRef{ref})
	linkage := e.linkageFor([]relational.ControlRef{ref}, ctype == relational.CatalogTypePolicy)
	if relational.IsOperationalCatalogType(ctype) {
		linkage.Unmapped = len(e.graph.ImplementsChildren(ref)) == 0 && len(e.filtersByControl[ref]) == 0
		// A graph-orphan control that an SSP nonetheless carries in its profile is
		// tracked there, not truly unmapped — drop the warning so it doesn't fire
		// once at least one SSP implements the control.
		if linkage.Unmapped && e.inAnySSPProfile(ref) {
			linkage.Unmapped = false
		}
	}
	// Children are the linked catalog groups (implementing/documenting controls
	// grouped by their catalog) PLUS this control's directly-linked risks. A
	// fully-compliant control also exposes its own compliance evidence (the
	// streams that make it satisfied) as leaf children.
	childCount := len(e.linkCatalogGroups(ref)) + e.distinctRiskCount(ref)
	if e.controlFullyCompliant(ref) {
		childCount += len(e.evidenceStreamsByControl[ref])
	}
	// nil in single-SSP scope; drives both the compliance pill and the bar globally.
	breakdown := e.sspBreakdownForSet(set)
	node := LineageNode{
		Key:           "control:" + ref.CatalogID.String() + "/" + ref.ControlID,
		NodeType:      controlNodeType(ctype),
		CatalogID:     ref.CatalogID.String(),
		ControlID:     ref.ControlID,
		Title:         e.controlTitle[ref],
		Statement:     e.controlStatement[ref],
		Compliance:    e.complianceFor(set, breakdown),
		Risk:          e.risk(set),
		Linkage:       linkage,
		HasChildren:   childCount > 0,
		ChildrenCount: childCount,
	}
	if e.sspID != nil {
		// Single-SSP posture overlay: operational controls always carry it (their
		// scope is the SSP's world, so even out-of-scope ones show as excluded); a
		// policy/procedure control gets it only when actually relevant — carried by a
		// profile or inheriting coverage through its implementers — so pure
		// documentation policies stay unadorned rather than reading as out-of-scope.
		operational := relational.IsOperationalCatalogType(ctype)
		st := e.controlSSPStatus(ref)
		if operational || st.InProfile {
			node.SSP = &st
		}
		// The same posture bar structural nodes and the global view carry: this
		// control's leaf implementers summed for the selected SSP (the single-SSP
		// slice of its global SSPBreakdown). Keeps a control's bar consistent whether
		// or not an SSP is filtered.
		node.PostureCounts = e.postureCountsFor([]relational.ControlRef{ref})
	} else {
		node.SSPBreakdown = breakdown
	}
	return node
}

// linkCatGroup is a set of a control's linked children that share a catalog and a
// relationship — rendered as one synthetic catalog node in the lineage tree.
type linkCatGroup struct {
	catalogID uuid.UUID
	rel       string // implements | documents
	children  []relational.ControlRef
}

// linkCatalogGroups groups a control's implementing/documenting children by their
// catalog (implements groups first, then documents), preserving edge order and
// de-duplicating within each group.
func (e *lineageEngine) linkCatalogGroups(ref relational.ControlRef) []linkCatGroup {
	group := func(children []relational.ControlRef, rel string) []linkCatGroup {
		order := []uuid.UUID{}
		byCat := map[uuid.UUID][]relational.ControlRef{}
		seen := map[relational.ControlRef]struct{}{}
		for _, child := range children {
			if _, dup := seen[child]; dup {
				continue
			}
			seen[child] = struct{}{}
			if _, ok := byCat[child.CatalogID]; !ok {
				order = append(order, child.CatalogID)
			}
			byCat[child.CatalogID] = append(byCat[child.CatalogID], child)
		}
		out := make([]linkCatGroup, 0, len(order))
		for _, cat := range order {
			out = append(out, linkCatGroup{catalogID: cat, rel: rel, children: byCat[cat]})
		}
		return out
	}
	groups := group(e.graph.ImplementsChildren(ref), relational.RelationshipImplements)
	return append(groups, group(e.graph.DocumentsChildren(ref), relational.RelationshipDocuments)...)
}

// linkCatNode builds the synthetic catalog node for one link group under a parent
// control. Its key encodes child catalog, relationship and the parent control so it
// expands back to exactly that group's controls.
func (e *lineageEngine) linkCatNode(parentRef relational.ControlRef, g linkCatGroup) LineageNode {
	info := e.catalogs[g.catalogID]
	set := e.evidenceSet(g.children)
	breakdown := e.sspBreakdownForSet(set)
	key := "linkcat:" + g.catalogID.String() + "/" + g.rel + "/" + parentRef.CatalogID.String() + "/" + parentRef.ControlID
	return LineageNode{
		Key:           key,
		NodeType:      catalogNodeType(info.ctype),
		Relationship:  g.rel,
		CatalogID:     g.catalogID.String(),
		Title:         info.title,
		Compliance:    e.complianceFor(set, breakdown),
		Risk:          e.risk(set),
		Linkage:       e.linkageFor(g.children, info.ctype == relational.CatalogTypePolicy),
		PostureCounts: e.postureCountsFor(g.children),
		SSPBreakdown:  breakdown,
		HasChildren:   len(g.children) > 0,
		ChildrenCount: len(g.children),
	}
}

// distinctRiskCount returns how many distinct risks are linked to a control
// (already scoped by loadRisks), for child counts.
func (e *lineageEngine) distinctRiskCount(ref relational.ControlRef) int {
	seen := map[uuid.UUID]struct{}{}
	for _, re := range e.risksByControl[ref] {
		seen[re.riskID] = struct{}{}
	}
	return len(seen)
}

// controlFullyCompliant reports whether a control's own evidence makes it fully
// satisfied (satisfied status with at least one matching stream).
func (e *lineageEngine) controlFullyCompliant(ref relational.ControlRef) bool {
	return e.controlStatus[ref] == relational.EvidenceStatusSatisfied &&
		len(e.evidenceStreamsByControl[ref]) > 0
}

// controlEvidenceNodes builds the evidence leaf nodes for a control's own
// compliance evidence (the latest streams matching its filters).
func (e *lineageEngine) controlEvidenceNodes(ref relational.ControlRef) []LineageNode {
	indices := e.evidenceStreamsByControl[ref]
	nodes := make([]LineageNode, 0, len(indices))
	for _, i := range indices {
		nodes = append(nodes, evidenceNodeFromStream(e.latestStreams[i]))
	}
	return nodes
}

func evidenceNodeFromStream(s relational.LatestEvidenceStream) LineageNode {
	collected := s.Collected
	return LineageNode{
		Key:          "evidence:" + s.UUID.String(),
		NodeType:     "evidence",
		Relationship: "has-evidence",
		EvidenceID:   s.ID.String(),
		Title:        s.Title,
		Status:       s.State,
		Reason:       s.Reason,
		CollectedAt:  &collected,
		Expires:      s.Expires,
	}
}

type riskRow struct {
	ID             uuid.UUID  `gorm:"column:id"`
	Title          string     `gorm:"column:title"`
	Status         string     `gorm:"column:status"`
	Likelihood     *string    `gorm:"column:likelihood"`
	Impact         *string    `gorm:"column:impact"`
	ReviewDeadline *time.Time `gorm:"column:review_deadline"`
	LastReviewedAt *time.Time `gorm:"column:last_reviewed_at"`
	FirstSeenAt    *time.Time `gorm:"column:first_seen_at"`
	LastSeenAt     *time.Time `gorm:"column:last_seen_at"`
	SSPID          uuid.UUID  `gorm:"column:ssp_id"`
}

// riskNodesForControl loads the risks directly linked to a control (same SSP/
// component scoping as loadRisks) as leaf-ish lineage nodes that expand to evidence.
func (e *lineageEngine) riskNodesForControl(ref relational.ControlRef) ([]LineageNode, error) {
	q := e.db.Table("risk_control_links rcl").
		Select("r.id, r.title, r.status, r.likelihood, r.impact, r.review_deadline, r.last_reviewed_at, r.first_seen_at, r.last_seen_at, r.ssp_id").
		Joins("JOIN risk_register_risks r ON r.id = rcl.risk_id").
		Where("rcl.catalog_id = ? AND rcl.control_id = ?", ref.CatalogID, ref.ControlID).
		// Closed risks are omitted as nodes (matches loadRisks / the child count).
		Where("r.status != ?", string(riskrel.RiskStatusClosed))
	if e.sspID != nil {
		q = q.Where("r.ssp_id = ?", *e.sspID)
	}
	if e.componentID != nil {
		q = q.Joins("JOIN risk_component_links rcomp ON rcomp.risk_id = r.id").
			Where("rcomp.component_id = ?", *e.componentID)
	}
	rows := []riskRow{}
	if err := q.Scan(&rows).Error; err != nil {
		return nil, err
	}

	seen := map[uuid.UUID]riskRow{}
	order := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		if _, ok := seen[r.ID]; !ok {
			seen[r.ID] = r
			order = append(order, r.ID)
		}
	}

	counts, err := e.riskEvidenceCounts(order)
	if err != nil {
		return nil, err
	}

	nodes := make([]LineageNode, 0, len(order))
	for _, id := range order {
		r := seen[id]
		nodes = append(nodes, riskNode(r, counts[id], e.sspTitles[r.SSPID]))
	}
	return nodes, nil
}

// riskEvidenceCounts returns the number of distinct linked evidence streams per
// risk, for the risk nodes' hasChildren/childrenCount.
func (e *lineageEngine) riskEvidenceCounts(riskIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	counts := map[uuid.UUID]int{}
	if len(riskIDs) == 0 {
		return counts, nil
	}
	rows := []struct {
		RiskID uuid.UUID `gorm:"column:risk_id"`
		C      int       `gorm:"column:c"`
	}{}
	if err := e.db.Table("risk_evidence_links").
		Select("risk_id, count(DISTINCT evidence_id) AS c").
		Where("risk_id IN ?", riskIDs).
		Group("risk_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		counts[r.RiskID] = r.C
	}
	return counts, nil
}

// evidenceNodesForRisk loads the latest evidence per stream linked to a risk.
func (e *lineageEngine) evidenceNodesForRisk(riskID uuid.UUID) ([]LineageNode, error) {
	rows := []struct {
		ID        uuid.UUID  `gorm:"column:id"`
		UUID      uuid.UUID  `gorm:"column:uuid"`
		Title     string     `gorm:"column:title"`
		State     string     `gorm:"column:state"`
		Reason    string     `gorm:"column:reason"`
		Collected time.Time  `gorm:"column:collected"`
		Expires   *time.Time `gorm:"column:expires"`
	}{}
	// evidences.uuid is text while risk_evidence_links.evidence_id is uuid; join
	// on text (the established repo convention for this mismatch). We pick the
	// latest record per stream (DISTINCT ON uuid) and expose that record's id so
	// the UI can deep-link to GET /evidence/{id} (which looks up by record id, not
	// the stream uuid).
	query := `
		SELECT DISTINCT ON (e.uuid) e.id AS id, e.uuid AS uuid, e.title AS title,
		       e.status->>'state' AS state, e.status->>'reason' AS reason,
		       e."end" AS collected, e.expires AS expires
		FROM risk_evidence_links rel
		JOIN evidences e ON e.uuid = rel.evidence_id::text
		WHERE rel.risk_id = ?
		ORDER BY e.uuid, e."end" DESC`
	if err := e.db.Raw(query, riskID).Scan(&rows).Error; err != nil {
		return nil, err
	}
	nodes := make([]LineageNode, 0, len(rows))
	for _, r := range rows {
		collected := r.Collected
		nodes = append(nodes, LineageNode{
			// Key stays the stream uuid (node identity / graph dedup), but the
			// EvidenceID is the record id so the UI links to GET /evidence/{id}.
			Key:          "evidence:" + r.UUID.String(),
			NodeType:     "evidence",
			Relationship: "has-evidence",
			EvidenceID:   r.ID.String(),
			Title:        r.Title,
			Status:       r.State,
			Reason:       r.Reason,
			CollectedAt:  &collected,
			Expires:      r.Expires,
		})
	}
	return nodes, nil
}

func riskNode(r riskRow, evidenceCount int, sspTitle string) LineageNode {
	score, _ := riskrel.NumericalRiskScore(r.Likelihood, r.Impact)
	s := score
	linked := evidenceCount
	node := LineageNode{
		Key:                 "risk:" + r.ID.String(),
		NodeType:            "risk",
		Relationship:        "has-risk",
		RiskID:              r.ID.String(),
		Title:               r.Title,
		Status:              r.Status,
		Severity:            severityForScore(score),
		Score:               &s,
		LinkedEvidenceCount: &linked,
		ReviewDeadline:      r.ReviewDeadline,
		LastReviewedAt:      r.LastReviewedAt,
		FirstSeenAt:         r.FirstSeenAt,
		LastSeenAt:          r.LastSeenAt,
		Risk:                bucketRisks([]riskEntry{{riskID: r.ID, status: r.Status, score: score}}),
		HasChildren:         evidenceCount > 0,
		ChildrenCount:       evidenceCount,
		RiskSSPID:           r.SSPID.String(),
		RiskSSPTitle:        sspTitle,
	}
	if r.Likelihood != nil {
		node.Likelihood = *r.Likelihood
	}
	if r.Impact != nil {
		node.Impact = *r.Impact
	}
	return node
}

// severityForScore bands the 1..25 likelihood×impact score into a categorical
// level for node coloring. 0 (unscored) yields "". Thresholds are a standard 5×5
// heat-map banding; the UI may re-band from the raw score/likelihood/impact.
func severityForScore(score int) string {
	switch {
	case score <= 0:
		return ""
	case score <= 2:
		return "negligible"
	case score <= 5:
		return "low"
	case score <= 11:
		return "moderate"
	case score <= 19:
		return "high"
	default:
		return "critical"
	}
}

func (e *lineageEngine) childrenOf(kind string, catalogID uuid.UUID, subID string) ([]LineageNode, error) {
	switch kind {
	case "catalog":
		if _, ok := e.catalogs[catalogID]; !ok {
			return nil, errors.New("catalog not found")
		}
		nodes := []LineageNode{}
		for _, g := range e.catalogTopGroups[catalogID] {
			n := e.groupNode(catalogID, g.ID)
			n.Relationship = "group"
			nodes = append(nodes, n)
		}
		for _, ref := range e.catalogTopControls[catalogID] {
			n := e.controlNode(ref)
			n.Relationship = "control"
			nodes = append(nodes, n)
		}
		return nodes, nil
	case "group":
		gkey := groupKey(catalogID, subID)
		if _, ok := e.groupControls[gkey]; !ok {
			return nil, errors.New("group not found")
		}
		// Direct children mirror the catalog hierarchy: sub-groups first (as group
		// nodes), then the controls held directly by this group.
		nodes := []LineageNode{}
		for _, sub := range e.groupChildGroups[gkey] {
			n := e.groupNode(catalogID, sub.ID)
			n.Relationship = "group"
			nodes = append(nodes, n)
		}
		for _, ref := range e.groupDirectControls[gkey] {
			n := e.controlNode(ref)
			n.Relationship = "control"
			nodes = append(nodes, n)
		}
		return nodes, nil
	case "control":
		ref := relational.ControlRef{CatalogID: catalogID, ControlID: subID}
		if _, ok := e.controlCatalogType[ref]; !ok {
			return nil, errors.New("control not found")
		}
		// Linked children are grouped by their catalog into synthetic catalog
		// nodes (implements groups first, then documents); the linked controls
		// themselves sit one level deeper under those nodes. Linked risks and this
		// control's own compliance evidence remain direct children.
		nodes := []LineageNode{}
		for _, g := range e.linkCatalogGroups(ref) {
			nodes = append(nodes, e.linkCatNode(ref, g))
		}
		riskNodes, err := e.riskNodesForControl(ref)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, riskNodes...)
		// A fully-compliant control also exposes its own compliance evidence.
		if e.controlFullyCompliant(ref) {
			nodes = append(nodes, e.controlEvidenceNodes(ref)...)
		}
		return nodes, nil
	case "linkcat":
		// subID is "<relationship>/<parentCatalogId>/<parentControlId>"; catalogID
		// is the child (linked) catalog. Return that group's linked controls.
		parts := strings.SplitN(subID, "/", 3)
		if len(parts) < 3 {
			return nil, errors.New("malformed linkcat key")
		}
		rel := parts[0]
		parentCat, perr := uuid.Parse(parts[1])
		if perr != nil {
			return nil, errors.New("malformed parent catalog id in linkcat key")
		}
		parentRef := relational.ControlRef{CatalogID: parentCat, ControlID: parts[2]}
		var linked []relational.ControlRef
		switch rel {
		case relational.RelationshipImplements:
			linked = e.graph.ImplementsChildren(parentRef)
		case relational.RelationshipDocuments:
			linked = e.graph.DocumentsChildren(parentRef)
		default:
			return nil, errors.New("unknown linkcat relationship: " + rel)
		}
		nodes := []LineageNode{}
		seen := map[relational.ControlRef]struct{}{}
		for _, child := range linked {
			if child.CatalogID != catalogID {
				continue
			}
			if _, dup := seen[child]; dup {
				continue
			}
			seen[child] = struct{}{}
			n := e.controlNode(child)
			n.Relationship = "control"
			nodes = append(nodes, n)
		}
		return nodes, nil
	case "risk":
		riskID, err := uuid.Parse(subID)
		if err != nil {
			return nil, errors.New("invalid risk id")
		}
		return e.evidenceNodesForRisk(riskID)
	case "evidence":
		// Evidence is a leaf.
		return []LineageNode{}, nil
	default:
		return nil, errors.New("unknown node kind: " + kind)
	}
}

// ── Pure helpers (unit-testable) ────────────────────────────────────────────────

// computeLineageStatus collapses a control's evidence status counts into one of
// satisfied/not-satisfied/unknown, identical to the profile compliance semantics:
// any not-satisfied wins; else any satisfied; else unknown.
func computeLineageStatus(rows []relational.StatusCount) string {
	hasSatisfied := false
	for _, row := range rows {
		if row.Count <= 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(row.Status)) {
		case relational.EvidenceStatusNotSatisfied:
			return relational.EvidenceStatusNotSatisfied
		case relational.EvidenceStatusSatisfied:
			hasSatisfied = true
		}
	}
	if hasSatisfied {
		return relational.EvidenceStatusSatisfied
	}
	return "unknown"
}

// bucketRisks dedups risks by id and buckets them by status into open (heat) and
// muted score sums, excluding remediated/closed risks entirely.
func bucketRisks(entries []riskEntry) LineageRisk {
	seen := map[uuid.UUID]struct{}{}
	var out LineageRisk
	for _, re := range entries {
		if _, ok := seen[re.riskID]; ok {
			continue
		}
		seen[re.riskID] = struct{}{}
		switch re.status {
		case string(riskrel.RiskStatusOpen):
			out.OpenScoreSum += re.score
			out.Counts.Open++
		case string(riskrel.RiskStatusInvestigating):
			out.OpenScoreSum += re.score
			out.Counts.Investigating++
		case string(riskrel.RiskStatusMitigatingPlanned):
			out.OpenScoreSum += re.score
			out.Counts.MitigatingPlanned++
		case string(riskrel.RiskStatusRiskAccepted):
			out.MutedScoreSum += re.score
			out.Counts.RiskAccepted++
		case string(riskrel.RiskStatusMitigatingImplemented):
			out.MutedScoreSum += re.score
			out.Counts.MitigatingImplemented++
		default:
			// remediated / closed / unknown: excluded from both sums.
		}
	}
	return out
}

func catalogNodeType(ctype string) string {
	switch ctype {
	case relational.CatalogTypePolicy:
		return "policy-catalog"
	case relational.CatalogTypeProcedure:
		return "procedure-catalog"
	default:
		return "standard-catalog"
	}
}

func controlNodeType(ctype string) string {
	switch ctype {
	case relational.CatalogTypePolicy:
		return "policy-control"
	case relational.CatalogTypeProcedure:
		return "procedure-control"
	default:
		return "control"
	}
}

// controlStatement extracts a control's requirement prose for hover/tooltip use.
// OSCAL models the requirement as a part named "statement" whose prose — often
// split across nested lettered/numbered item parts — is the human-readable text.
// Returns "" when the control carries no statement part.
func controlStatement(c relational.Control) string {
	for _, p := range c.Parts {
		if p.Name == "statement" {
			return strings.TrimSpace(partProse(p))
		}
	}
	return ""
}

// partProse concatenates a part's prose with its descendants' prose depth-first,
// so a statement broken into item sub-parts renders as one block.
func partProse(p relational.Part) string {
	var b strings.Builder
	appendProse := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString(s)
	}
	appendProse(p.Prose)
	for _, sub := range p.Parts {
		appendProse(partProse(sub))
	}
	return b.String()
}

func groupKey(catID uuid.UUID, groupID string) string {
	return catID.String() + "/" + groupID
}

func scopeKey(ref relational.ControlRef) string {
	return ref.CatalogID.String() + "\x00" + strings.ToUpper(ref.ControlID)
}

func pct1(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(part)/float64(total)*1000) / 10
}

func sortNodes(nodes []LineageNode) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Title == nodes[j].Title {
			return nodes[i].Key < nodes[j].Key
		}
		return nodes[i].Title < nodes[j].Title
	})
}

// parseScope parses the shared sspId/componentId query params.
func parseScope(ctx echo.Context) (*uuid.UUID, *uuid.UUID, error) {
	var sspID, componentID *uuid.UUID
	if v := strings.TrimSpace(ctx.QueryParam("sspId")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, errors.New("invalid sspId")
		}
		sspID = &id
	}
	if v := strings.TrimSpace(ctx.QueryParam("componentId")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, errors.New("invalid componentId")
		}
		componentID = &id
	}
	return sspID, componentID, nil
}

// parseTypes parses the roots ?types= filter, defaulting to all catalog types.
func parseTypes(raw string) (map[string]struct{}, error) {
	types := map[string]struct{}{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		for _, t := range relational.AllCatalogTypes {
			types[t] = struct{}{}
		}
		return types, nil
	}
	for _, part := range strings.Split(raw, ",") {
		t := strings.TrimSpace(part)
		if t == "" {
			continue
		}
		if !relational.IsValidCatalogType(t) {
			return nil, errors.New("invalid catalog type in types filter: " + t)
		}
		types[t] = struct{}{}
	}
	if len(types) == 0 {
		return nil, errors.New("types filter is empty")
	}
	return types, nil
}

// parseNodeKey decodes a composite node key into its kind, catalog id, and the
// trailing sub-id. For risk/evidence keys (risk:<uuid>, evidence:<uuid>) the id
// is returned in subID and catalogID is Nil.
//
// The key travels as a single URL-encoded path segment (the ':' and the '/'
// separator arrive as %3A/%2F). Echo does not unescape path params, so we decode
// here before splitting. A raw, unencoded key contains no '%' and passes through
// url.PathUnescape unchanged, so direct callers keep working.
func parseNodeKey(raw string) (kind string, catalogID uuid.UUID, subID string, err error) {
	if decoded, derr := url.PathUnescape(raw); derr == nil {
		raw = decoded
	}
	colon := strings.IndexByte(raw, ':')
	if colon < 0 {
		return "", uuid.Nil, "", errors.New("malformed node key")
	}
	kind = raw[:colon]
	rest := raw[colon+1:]

	switch kind {
	case "catalog":
		catalogID, err = uuid.Parse(rest)
		if err != nil {
			return "", uuid.Nil, "", errors.New("malformed catalog key")
		}
		return kind, catalogID, "", nil
	case "risk", "evidence":
		if rest == "" {
			return "", uuid.Nil, "", errors.New("missing id in " + kind + " key")
		}
		return kind, uuid.Nil, rest, nil
	case "group", "control", "linkcat":
		// catalogID is the UUID before the first '/'; subID is the remainder (a
		// control id, or for linkcat "<rel>/<parentCatalogId>/<parentControlId>").
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			return "", uuid.Nil, "", errors.New("malformed " + kind + " key")
		}
		catalogID, err = uuid.Parse(rest[:slash])
		if err != nil {
			return "", uuid.Nil, "", errors.New("malformed catalog id in key")
		}
		subID = rest[slash+1:]
		if subID == "" {
			return "", uuid.Nil, "", errors.New("missing sub-id in key")
		}
		return kind, catalogID, subID, nil
	default:
		return "", uuid.Nil, "", errors.New("unknown node kind: " + kind)
	}
}
