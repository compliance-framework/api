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
}

// ── Response shapes ────────────────────────────────────────────────────────────

type LineageCompliance struct {
	TotalControls     int     `json:"totalControls"`
	Satisfied         int     `json:"satisfied"`
	NotSatisfied      int     `json:"notSatisfied"`
	Unknown           int     `json:"unknown"`
	CompliancePercent float64 `json:"compliancePercent"`
	AssessedPercent   float64 `json:"assessedPercent"`
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
	Status       string `json:"status,omitempty"`

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

	// Evidence-node detail.
	Reason      string     `json:"reason,omitempty"`
	CollectedAt *time.Time `json:"collectedAt,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`

	Compliance    LineageCompliance `json:"compliance"`
	Risk          LineageRisk       `json:"risk"`
	Linkage       LineageLinkage    `json:"linkage"`
	HasChildren   bool              `json:"hasChildren"`
	ChildrenCount int               `json:"childrenCount"`
}

// ── Endpoints ──────────────────────────────────────────────────────────────────

// Roots godoc

// @Summary		List lineage roots
// @Description	Returns catalog roots (standard/policy/procedure) with full-subtree compliance and risk rollups. Rootness is catalog_type, never link presence.
// @Tags			Lineage
// @Produce		json
// @Param			sspId		query		string	false	"Scope metrics to a System Security Plan"
// @Param			componentId	query		string	false	"Scope metrics to a system component"
// @Param			types		query		string	false	"Comma-separated catalog types to include (standard,policy,procedure)"
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
// @Description	Returns one level of children for a node. Key is a composite like catalog:<uuid>, group:<catalogId>/<groupId>, control:<catalogId>/<controlId>, risk:<riskId>, evidence:<streamUuid>. A control expands to its implementing/documenting controls plus its directly-linked risks; a risk expands to its latest evidence per linked stream; evidence is a leaf.
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

// ── Engine ─────────────────────────────────────────────────────────────────────

type catalogInfo struct {
	ctype string
	title string
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
	controlCatalogType map[relational.ControlRef]string
	standardCatalogs   map[uuid.UUID]struct{}

	catalogAllControls map[uuid.UUID][]relational.ControlRef
	catalogTopControls map[uuid.UUID][]relational.ControlRef
	catalogTopGroups   map[uuid.UUID][]groupMeta
	groupControls      map[string][]relational.ControlRef
	groupTitle         map[string]string

	// rollup inputs
	filtersByControl map[relational.ControlRef][]uuid.UUID
	statusByFilter   map[uuid.UUID][]relational.StatusCount
	controlStatus    map[relational.ControlRef]string
	risksByControl   map[relational.ControlRef][]riskEntry

	// SSP scope: standard controls resolved by the SSP's profiles.
	profileControlSet map[string]struct{}
}

func (h *LineageHandler) buildEngine(sspID, componentID *uuid.UUID) (*lineageEngine, error) {
	e := &lineageEngine{
		db:                 h.db,
		sspID:              sspID,
		componentID:        componentID,
		catalogs:           map[uuid.UUID]catalogInfo{},
		controlTitle:       map[relational.ControlRef]string{},
		controlCatalogType: map[relational.ControlRef]string{},
		standardCatalogs:   map[uuid.UUID]struct{}{},
		catalogAllControls: map[uuid.UUID][]relational.ControlRef{},
		catalogTopControls: map[uuid.UUID][]relational.ControlRef{},
		catalogTopGroups:   map[uuid.UUID][]groupMeta{},
		groupControls:      map[string][]relational.ControlRef{},
		groupTitle:         map[string]string{},
		filtersByControl:   map[relational.ControlRef][]uuid.UUID{},
		controlStatus:      map[relational.ControlRef]string{},
		risksByControl:     map[relational.ControlRef][]riskEntry{},
		profileControlSet:  map[string]struct{}{},
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
	if sspID != nil {
		if err := e.loadProfileScope(h.db, *sspID); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (e *lineageEngine) loadCatalogs(db *gorm.DB) error {
	var catalogs []relational.Catalog
	if err := db.
		Preload("Metadata").
		Preload("Controls").
		Preload("Groups").
		Preload("Groups.Controls").
		Preload("Groups.Groups").
		Preload("Groups.Groups.Controls").
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
		e.catalogs[catID] = catalogInfo{ctype: ctype, title: cat.Metadata.Title}
		if ctype == relational.CatalogTypeStandard {
			e.standardCatalogs[catID] = struct{}{}
		}

		register := func(ref relational.ControlRef, title string) {
			e.controlTitle[ref] = title
			e.controlCatalogType[ref] = ctype
		}

		// Load groups first and record which controls belong to a group. GORM's
		// Preload("Controls") on a catalog returns EVERY control by catalog_id —
		// including grouped ones — so a control's group membership is the only way
		// to tell true top-level controls from grouped ones.
		inGroup := map[relational.ControlRef]struct{}{}
		allControls := []relational.ControlRef{}
		for _, g := range cat.Groups {
			var gc []relational.ControlRef
			flattenGroup(g, catID, &gc, register)
			gkey := groupKey(catID, g.ID)
			e.groupControls[gkey] = gc
			e.groupTitle[gkey] = g.Title
			e.catalogTopGroups[catID] = append(e.catalogTopGroups[catID], groupMeta{ID: g.ID, Title: g.Title})
			for _, ref := range gc {
				if _, seen := inGroup[ref]; !seen {
					inGroup[ref] = struct{}{}
					allControls = append(allControls, ref)
				}
			}
		}

		// Top-level controls are the catalog's controls that are NOT in any group,
		// so a grouped control appears only under its group, never at catalog level.
		var catControls []relational.ControlRef
		flattenControls(cat.Controls, catID, &catControls, register)
		topControls := []relational.ControlRef{}
		for _, ref := range catControls {
			if _, grouped := inGroup[ref]; grouped {
				continue
			}
			topControls = append(topControls, ref)
			allControls = append(allControls, ref)
		}
		e.catalogTopControls[catID] = topControls
		e.catalogAllControls[catID] = allControls
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

	filterMap := make(map[uuid.UUID]labelfilter.Filter, len(filters))
	for i := range filters {
		f := filters[i]
		if f.ID == nil {
			continue
		}
		filterMap[*f.ID] = f.Filter.Data()
		for _, c := range f.Controls {
			ref := relational.ControlRef{CatalogID: c.CatalogID, ControlID: c.ID}
			e.filtersByControl[ref] = append(e.filtersByControl[ref], *f.ID)
		}
	}

	statusByFilter, err := relational.GetEvidenceStatusCountsByFilters(db, filterMap, e.componentID)
	if err != nil {
		return err
	}
	e.statusByFilter = statusByFilter

	for ref, ids := range e.filtersByControl {
		merged := make([]relational.StatusCount, 0)
		for _, id := range ids {
			merged = append(merged, statusByFilter[id]...)
		}
		e.controlStatus[ref] = computeLineageStatus(merged)
	}
	return nil
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
		Joins("JOIN risk_register_risks r ON r.id = rcl.risk_id")
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

func (e *lineageEngine) compliance(set map[relational.ControlRef]struct{}) LineageCompliance {
	total, sat, not, unk := 0, 0, 0, 0
	for ref := range set {
		total++
		switch e.controlStatus[ref] {
		case relational.EvidenceStatusSatisfied:
			sat++
		case relational.EvidenceStatusNotSatisfied:
			not++
		default:
			unk++
		}
	}
	return LineageCompliance{
		TotalControls:     total,
		Satisfied:         sat,
		NotSatisfied:      not,
		Unknown:           unk,
		CompliancePercent: pct1(sat, total),
		AssessedPercent:   pct1(sat+not, total),
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
	childCount := len(e.catalogTopGroups[catID]) + len(e.catalogTopControls[catID])
	return LineageNode{
		Key:           "catalog:" + catID.String(),
		NodeType:      catalogNodeType(info.ctype),
		CatalogID:     catID.String(),
		Title:         info.title,
		Compliance:    e.compliance(set),
		Risk:          e.risk(set),
		Linkage:       e.linkageFor(seeds, info.ctype == relational.CatalogTypePolicy),
		HasChildren:   childCount > 0,
		ChildrenCount: childCount,
	}
}

func (e *lineageEngine) groupNode(catID uuid.UUID, groupID string) LineageNode {
	seeds := e.groupControls[groupKey(catID, groupID)]
	set := e.evidenceSet(seeds)
	return LineageNode{
		Key:           "group:" + catID.String() + "/" + groupID,
		NodeType:      "group",
		CatalogID:     catID.String(),
		GroupID:       groupID,
		Title:         e.groupTitle[groupKey(catID, groupID)],
		Compliance:    e.compliance(set),
		Risk:          e.risk(set),
		Linkage:       e.linkageFor(seeds, false),
		HasChildren:   len(seeds) > 0,
		ChildrenCount: len(seeds),
	}
}

func (e *lineageEngine) controlNode(ref relational.ControlRef) LineageNode {
	ctype := e.controlCatalogType[ref]
	set := e.evidenceSet([]relational.ControlRef{ref})
	linkage := e.linkageFor([]relational.ControlRef{ref}, ctype == relational.CatalogTypePolicy)
	if ctype == relational.CatalogTypeStandard {
		linkage.Unmapped = len(e.graph.ImplementsChildren(ref)) == 0 && len(e.filtersByControl[ref]) == 0
	}
	// Children are the implementing/documenting controls PLUS this control's
	// directly-linked risks (leaf risks, which in turn expand to their evidence).
	childCount := len(e.graph.Children(ref)) + e.distinctRiskCount(ref)
	return LineageNode{
		Key:           "control:" + ref.CatalogID.String() + "/" + ref.ControlID,
		NodeType:      controlNodeType(ctype),
		CatalogID:     ref.CatalogID.String(),
		ControlID:     ref.ControlID,
		Title:         e.controlTitle[ref],
		Compliance:    e.compliance(set),
		Risk:          e.risk(set),
		Linkage:       linkage,
		HasChildren:   childCount > 0,
		ChildrenCount: childCount,
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
}

// riskNodesForControl loads the risks directly linked to a control (same SSP/
// component scoping as loadRisks) as leaf-ish lineage nodes that expand to evidence.
func (e *lineageEngine) riskNodesForControl(ref relational.ControlRef) ([]LineageNode, error) {
	q := e.db.Table("risk_control_links rcl").
		Select("r.id, r.title, r.status, r.likelihood, r.impact, r.review_deadline, r.last_reviewed_at, r.first_seen_at, r.last_seen_at").
		Joins("JOIN risk_register_risks r ON r.id = rcl.risk_id").
		Where("rcl.catalog_id = ? AND rcl.control_id = ?", ref.CatalogID, ref.ControlID)
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
		nodes = append(nodes, riskNode(r, counts[id]))
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
		UUID      uuid.UUID  `gorm:"column:uuid"`
		Title     string     `gorm:"column:title"`
		State     string     `gorm:"column:state"`
		Reason    string     `gorm:"column:reason"`
		Collected time.Time  `gorm:"column:collected"`
		Expires   *time.Time `gorm:"column:expires"`
	}{}
	// evidences.uuid is text while risk_evidence_links.evidence_id is uuid; join
	// on text (the established repo convention for this mismatch).
	query := `
		SELECT DISTINCT ON (e.uuid) e.uuid AS uuid, e.title AS title,
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
			Key:          "evidence:" + r.UUID.String(),
			NodeType:     "evidence",
			Relationship: "has-evidence",
			EvidenceID:   r.UUID.String(),
			Title:        r.Title,
			Status:       r.State,
			Reason:       r.Reason,
			CollectedAt:  &collected,
			Expires:      r.Expires,
		})
	}
	return nodes, nil
}

func riskNode(r riskRow, evidenceCount int) LineageNode {
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
		refs, ok := e.groupControls[groupKey(catalogID, subID)]
		if !ok {
			return nil, errors.New("group not found")
		}
		nodes := make([]LineageNode, 0, len(refs))
		for _, ref := range refs {
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
		// Implementing controls, then documenting controls, then linked risks —
		// each child labelled with how it relates to this control.
		nodes := []LineageNode{}
		seen := map[relational.ControlRef]struct{}{}
		for _, child := range e.graph.ImplementsChildren(ref) {
			if _, dup := seen[child]; dup {
				continue
			}
			seen[child] = struct{}{}
			n := e.controlNode(child)
			n.Relationship = "implements"
			nodes = append(nodes, n)
		}
		for _, child := range e.graph.DocumentsChildren(ref) {
			if _, dup := seen[child]; dup {
				continue
			}
			seen[child] = struct{}{}
			n := e.controlNode(child)
			n.Relationship = "documents"
			nodes = append(nodes, n)
		}
		riskNodes, err := e.riskNodesForControl(ref)
		if err != nil {
			return nil, err
		}
		return append(nodes, riskNodes...), nil
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

func flattenControls(controls []relational.Control, catID uuid.UUID, out *[]relational.ControlRef, register func(relational.ControlRef, string)) {
	for _, c := range controls {
		ref := relational.ControlRef{CatalogID: catID, ControlID: c.ID}
		*out = append(*out, ref)
		register(ref, c.Title)
		if len(c.Controls) > 0 {
			flattenControls(c.Controls, catID, out, register)
		}
	}
}

func flattenGroup(g relational.Group, catID uuid.UUID, out *[]relational.ControlRef, register func(relational.ControlRef, string)) {
	flattenControls(g.Controls, catID, out, register)
	for _, sub := range g.Groups {
		flattenGroup(sub, catID, out, register)
	}
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
		types[relational.CatalogTypeStandard] = struct{}{}
		types[relational.CatalogTypePolicy] = struct{}{}
		types[relational.CatalogTypeProcedure] = struct{}{}
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
	case "group", "control":
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
