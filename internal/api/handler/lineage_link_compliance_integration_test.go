//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func TestLineageLinkCompliance(t *testing.T) {
	suite.Run(t, new(LineageLinkComplianceSuite))
}

type LineageLinkComplianceSuite struct {
	tests.IntegrationTestSuite
}

func (suite *LineageLinkComplianceSuite) childrenOf(key string) []LineageNode {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("key")
	ctx.SetParamValues(key)
	suite.Require().NoError(NewLineageHandler(zap.NewNop().Sugar(), suite.DB).Children(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func (suite *LineageLinkComplianceSuite) ssps(key string) []LineageSSPRow {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("key")
	ctx.SetParamValues(key)
	suite.Require().NoError(NewLineageHandler(zap.NewNop().Sugar(), suite.DB).SSPDetail(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []LineageSSPRow `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func (suite *LineageLinkComplianceSuite) roots() []LineageNode {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	suite.Require().NoError(NewLineageHandler(zap.NewNop().Sugar(), suite.DB).Roots(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// A standard control satisfied indirectly through a control-link must not count
// ITSELF as an unknown: its compliance is the sum of its implementers only. A
// standalone control with no links still counts its own (unknown) status.
func (suite *LineageLinkComplianceSuite) TestLinkedControlDoesNotSelfCountUnknown() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	stdCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &stdCat},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls: []relational.Control{
			{CatalogID: stdCat, ID: "std-linked", Title: "Satisfied via a link"},
			{CatalogID: stdCat, ID: "std-lonely", Title: "No links, no evidence"},
		},
	}).Error)

	// An internal control implements the linked standard control and carries the
	// only real evidence.
	intCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &intCat},
		CatalogType: relational.CatalogTypeInternal,
		Metadata:    relational.Metadata{Title: "Int", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: intCat, ID: "op-1", Title: "Concrete control"}},
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.ControlLink{
		SourceCatalogID:  intCat,
		SourceControlID:  "op-1",
		TargetCatalogID:  stdCat,
		TargetControlID:  "std-linked",
		RelationshipType: relational.RelationshipImplements,
	}).Error)

	f := relational.Filter{
		Name: "op-filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "op"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, intCat, "op-1").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "op-ev",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'op') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'op')", evID).Error)

	nodes := byControlID(suite.childrenOf("catalog:" + stdCat.String()))

	// The linked standard control's score is the sum of its implementers only:
	// one satisfied control, and crucially NOT an extra unknown for itself.
	linked := nodes["std-linked"].Compliance
	suite.Equal(1, linked.TotalControls, "the abstract control itself must not be counted")
	suite.Equal(1, linked.Satisfied)
	suite.Equal(0, linked.Unknown)
	suite.Equal(float64(100), linked.CompliancePercent)

	// A standalone control with no links still counts its own unknown status.
	lonely := nodes["std-lonely"].Compliance
	suite.Equal(1, lonely.TotalControls)
	suite.Equal(1, lonely.Unknown)
	suite.Equal(0, lonely.Satisfied)
}

// Every node's cross-SSP breakdown is the sum of its leaf controls over every SSP:
// a standard control (and its catalog) implemented by two operational leaves shows
// 2 controls × 2 SSPs = 4 cells, aggregated from the leaves — not a single rolled
// up posture, and not counting the abstract control itself.
func (suite *LineageLinkComplianceSuite) TestBreakdownAggregatesLeavesAcrossSSPs() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	stdCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &stdCat},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: stdCat, ID: "std-1", Title: "Abstract"}},
	}).Error)

	intCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &intCat},
		CatalogType: relational.CatalogTypeInternal,
		Metadata:    relational.Metadata{Title: "Int", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls: []relational.Control{
			{CatalogID: intCat, ID: "op-1", Title: "Leaf one"},
			{CatalogID: intCat, ID: "op-2", Title: "Leaf two"},
		},
	}).Error)
	for _, op := range []string{"op-1", "op-2"} {
		suite.Require().NoError(suite.DB.Create(&relational.ControlLink{
			SourceCatalogID:  intCat,
			SourceControlID:  op,
			TargetCatalogID:  stdCat,
			TargetControlID:  "std-1",
			RelationshipType: relational.RelationshipImplements,
		}).Error)
	}

	// SSP #1 carries both leaves in its profile; SSP #2 carries neither (bare plan).
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	for _, op := range []string{"op-1", "op-2"} {
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
			profileID, intCat, op).Error)
	}
	ssp1 := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &ssp1},
		Metadata:  relational.Metadata{Title: "S1", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		ssp1, profileID).Error)
	ssp2 := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &ssp2},
		Metadata:  relational.Metadata{Title: "S2", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)

	// op-1 has satisfying evidence; op-2 has none (attention where it's in scope).
	f := relational.Filter{
		Name: "op1-filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "op1"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, intCat, "op-1").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "op1-ev",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'op1') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'op1')", evID).Error)

	// The standard control aggregates its two leaves across both SSPs: op-1 satisfied
	// in SSP1 (out of scope in SSP2), op-2 attention in SSP1 (out of scope in SSP2).
	assertAggregate := func(b *LineageSSPBreakdown, label string) {
		suite.Require().NotNilf(b, "%s should carry a cross-SSP breakdown", label)
		suite.Equalf(2, b.TotalSSPs, "%s totalSsps", label)
		suite.Equalf(1, b.Satisfied, "%s satisfied", label)
		suite.Equalf(1, b.Attention, "%s attention", label)
		suite.Equalf(2, b.OutOfScope, "%s out of scope", label)
		suite.Equalf(0, b.NotSatisfied+b.NotApplicable+b.Planned, "%s other buckets", label)
	}

	std := byControlID(suite.childrenOf("catalog:" + stdCat.String()))["std-1"]
	assertAggregate(std.SSPBreakdown, "std-1 control node")

	// The standard catalog (a structural node) carries the same sum — it now has a bar.
	var stdRoot *LineageNode
	for _, r := range suite.roots() {
		if r.CatalogID == stdCat.String() {
			r := r
			stdRoot = &r
		}
	}
	suite.Require().NotNil(stdRoot)
	assertAggregate(stdRoot.SSPBreakdown, "standard catalog node")
}

// The global compliance pill counts per (control, SSP), so a control failing in one
// SSP and satisfied in another shows as BOTH — one SSP's evidence must not overwrite
// the other's in the collapsed score.
func (suite *LineageLinkComplianceSuite) TestComplianceIsPerSSPNotCollapsed() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: catID, ID: "shared", Title: "In two SSPs"}},
	}).Error)

	// One profile carried by both SSPs, so the control is in scope in each.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID, catID, "shared").Error)
	sspFail := uuid.New()
	sspPass := uuid.New()
	for _, id := range []uuid.UUID{sspFail, sspPass} {
		id := id
		suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
			UUIDModel: relational.UUIDModel{ID: &id},
			Metadata:  relational.Metadata{Title: "S", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		}).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
			id, profileID).Error)
	}

	// An SSP-scoped filter + evidence per plan: failing in one, satisfying in the other.
	mkScoped := func(sspID uuid.UUID, label, state string) {
		f := relational.Filter{
			Name:  "f-" + label,
			SSPID: &sspID,
			Filter: datatypes.NewJSONType(labelfilter.Filter{
				Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: label}},
			}),
		}
		suite.Require().NoError(suite.DB.Create(&f).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
			f.ID, catID, "shared").Error)
		evID := uuid.New()
		suite.Require().NoError(suite.DB.Create(&relational.Evidence{
			UUIDModel: relational.UUIDModel{ID: &evID},
			UUID:      uuid.New(),
			Title:     "ev-" + label,
			Start:     now, End: now, Expires: &now,
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: state, Reason: "auto"}),
		}).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO labels (name, value) VALUES ('ctrl', ?) ON CONFLICT DO NOTHING", label).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', ?)", evID, label).Error)
	}
	mkScoped(sspFail, "fail", "not-satisfied")
	mkScoped(sspPass, "pass", "satisfied")

	shared := byControlID(suite.childrenOf("catalog:" + catID.String()))["shared"]

	// Per-SSP: one satisfied cell and one not-satisfied cell coexist — NOT collapsed
	// to a single not-satisfied (which the old global status would have produced).
	c := shared.Compliance
	suite.Equal(2, c.TotalControls, "two (control, SSP) cells")
	suite.Equal(1, c.Satisfied)
	suite.Equal(1, c.NotSatisfied)
	suite.Equal(0, c.Unknown)
	suite.Equal(float64(50), c.CompliancePercent)

	suite.Require().NotNil(shared.SSPBreakdown)
	suite.Equal(1, shared.SSPBreakdown.Satisfied)
	suite.Equal(1, shared.SSPBreakdown.NotSatisfied)
	suite.Equal(0, shared.SSPBreakdown.OutOfScope)
}

// The per-SSP drawer endpoint returns one row per plan with that plan's title,
// evidence status and declared implementation status — a control satisfied by
// evidence in one plan and marked not-applicable in another shows both distinctly.
func (suite *LineageLinkComplianceSuite) TestSSPDetailRows() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: catID, ID: "c", Title: "Control"}},
	}).Error)

	// One profile carried by both plans, so the control is in scope in each.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID, catID, "c").Error)

	sspEvidence := uuid.New() // satisfied via evidence
	sspNA := uuid.New()       // marked not-applicable
	mkSSP := func(id uuid.UUID, title string) {
		suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
			UUIDModel: relational.UUIDModel{ID: &id},
			Metadata:  relational.Metadata{Title: title, Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		}).Error)
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
			id, profileID).Error)
	}
	mkSSP(sspEvidence, "Evidence Plan")
	mkSSP(sspNA, "Not Applicable Plan")

	// Satisfying evidence scoped to the first plan only.
	f := relational.Filter{
		Name:  "ev-filter",
		SSPID: &sspEvidence,
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "c"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, catID, "c").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "ev",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'c') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'c')", evID).Error)

	// The second plan declares the control not-applicable via a by-component.
	ci := relational.ControlImplementation{Description: "ci", SystemSecurityPlanId: sspNA}
	suite.Require().NoError(suite.DB.Create(&ci).Error)
	ir := relational.ImplementedRequirement{ControlId: "c", ControlImplementationId: *ci.ID}
	suite.Require().NoError(suite.DB.Create(&ir).Error)
	pt := "implemented_requirements"
	bcID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.ByComponent{
		UUIDModel:            relational.UUIDModel{ID: &bcID},
		ParentID:             ir.ID,
		ParentType:           &pt,
		ComponentUUID:        uuid.New(),
		ImplementationStatus: datatypes.NewJSONType(relational.ImplementationStatus{State: relational.ImplementationStatusNotApplicable}),
	}).Error)

	rows := suite.ssps("control:" + catID.String() + "/c")
	suite.Require().Len(rows, 2)
	byTitle := map[string]LineageSSPRow{}
	for _, r := range rows {
		byTitle[r.SSPTitle] = r
	}

	ev := byTitle["Evidence Plan"]
	suite.True(ev.InProfile)
	suite.Equal(PostureSatisfied, ev.Posture)
	suite.Equal(relational.EvidenceStatusSatisfied, ev.EvidenceStatus)

	na := byTitle["Not Applicable Plan"]
	suite.True(na.InProfile)
	suite.Equal(PostureNotApplicable, na.Posture)
	suite.Equal("unknown", na.EvidenceStatus)
	suite.Equal(string(relational.ImplementationStatusNotApplicable), na.ImplementationStatus)
}
