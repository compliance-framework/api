package handler

import (
	"errors"
	"math"
	"net/http"
	"sort"
	"strings"

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
	Key           string            `json:"key"`
	NodeType      string            `json:"nodeType"`
	CatalogID     string            `json:"catalogId,omitempty"`
	ControlID     string            `json:"controlId,omitempty"`
	GroupID       string            `json:"groupId,omitempty"`
	Title         string            `json:"title"`
	Compliance    LineageCompliance `json:"compliance"`
	Risk          LineageRisk       `json:"risk"`
	Linkage       LineageLinkage    `json:"linkage"`
	HasChildren   bool              `json:"hasChildren"`
	ChildrenCount int               `json:"childrenCount"`
}

// ── Endpoints ──────────────────────────────────────────────────────────────────

// Roots godoc
//
//	@Summary		List lineage roots
//	@Description	Returns catalog roots (standard/policy/procedure) with full-subtree compliance and risk rollups. Rootness is catalog_type, never link presence.
//	@Tags			Lineage
//	@Produce		json
//	@Param			sspId		query	string	false	"Scope metrics to a System Security Plan"
//	@Param			componentId	query	string	false	"Scope metrics to a system component"
//	@Param			types		query	string	false	"Comma-separated catalog types to include (standard,policy,procedure)"
//	@Success		200	{object}	handler.GenericDataListResponse[LineageNode]
//	@Failure		400	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/lineage/roots [get]
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

	return ctx.JSON(http.StatusOK, GenericDataListResponse[LineageNode]{Data: nodes})
}

// Children godoc
//
//	@Summary		List lineage node children
//	@Description	Returns one level of children for a node. Every node carries full-subtree rollup metrics. Key is a composite like catalog:<uuid>, group:<catalogId>/<groupId>, control:<catalogId>/<controlId>.
//	@Tags			Lineage
//	@Produce		json
//	@Param			key			path	string	true	"URL-encoded node key"
//	@Param			sspId		query	string	false	"Scope metrics to a System Security Plan"
//	@Param			componentId	query	string	false	"Scope metrics to a system component"
//	@Param			page		query	int		false	"Page number"
//	@Param			limit		query	int		false	"Page size (default 100)"
//	@Success		200	{object}	service.ListResponse[LineageNode]
//	@Failure		400	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/lineage/nodes/{key}/children [get]
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

		var topControls []relational.ControlRef
		flattenControls(cat.Controls, catID, &topControls, register)
		e.catalogTopControls[catID] = topControls

		allControls := append([]relational.ControlRef(nil), topControls...)
		for _, g := range cat.Groups {
			var gc []relational.ControlRef
			flattenGroup(g, catID, &gc, register)
			gkey := groupKey(catID, g.ID)
			e.groupControls[gkey] = gc
			e.groupTitle[gkey] = g.Title
			e.catalogTopGroups[catID] = append(e.catalogTopGroups[catID], groupMeta{ID: g.ID, Title: g.Title})
			allControls = append(allControls, gc...)
		}
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
	children := e.graph.Children(ref)
	linkage := e.linkageFor([]relational.ControlRef{ref}, ctype == relational.CatalogTypePolicy)
	if ctype == relational.CatalogTypeStandard {
		linkage.Unmapped = len(e.graph.ImplementsChildren(ref)) == 0 && len(e.filtersByControl[ref]) == 0
	}
	return LineageNode{
		Key:           "control:" + ref.CatalogID.String() + "/" + ref.ControlID,
		NodeType:      controlNodeType(ctype),
		CatalogID:     ref.CatalogID.String(),
		ControlID:     ref.ControlID,
		Title:         e.controlTitle[ref],
		Compliance:    e.compliance(set),
		Risk:          e.risk(set),
		Linkage:       linkage,
		HasChildren:   len(children) > 0,
		ChildrenCount: len(children),
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
			nodes = append(nodes, e.groupNode(catalogID, g.ID))
		}
		for _, ref := range e.catalogTopControls[catalogID] {
			nodes = append(nodes, e.controlNode(ref))
		}
		return nodes, nil
	case "group":
		refs, ok := e.groupControls[groupKey(catalogID, subID)]
		if !ok {
			return nil, errors.New("group not found")
		}
		nodes := make([]LineageNode, 0, len(refs))
		for _, ref := range refs {
			nodes = append(nodes, e.controlNode(ref))
		}
		return nodes, nil
	case "control":
		ref := relational.ControlRef{CatalogID: catalogID, ControlID: subID}
		if _, ok := e.controlCatalogType[ref]; !ok {
			return nil, errors.New("control not found")
		}
		children := e.graph.Children(ref)
		nodes := make([]LineageNode, 0, len(children))
		for _, child := range children {
			nodes = append(nodes, e.controlNode(child))
		}
		return nodes, nil
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
// trailing sub-id (group id or control id).
func parseNodeKey(raw string) (kind string, catalogID uuid.UUID, subID string, err error) {
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
