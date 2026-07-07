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

func TestLineagePosture(t *testing.T) {
	suite.Run(t, new(LineagePostureSuite))
}

type LineagePostureSuite struct {
	tests.IntegrationTestSuite
}

// childrenOf fetches a node's children, optionally scoped to an SSP.
func (suite *LineagePostureSuite) childrenOf(key, sspID string) []LineageNode {
	url := "/x"
	if sspID != "" {
		url += "?sspId=" + sspID
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, url, nil)
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

func (suite *LineagePostureSuite) roots(sspID string) []LineageNode {
	url := "/x"
	if sspID != "" {
		url += "?sspId=" + sspID
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, url, nil)
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

func byControlID(nodes []LineageNode) map[string]LineageNode {
	out := map[string]LineageNode{}
	for _, n := range nodes {
		if n.ControlID != "" {
			out[n.ControlID] = n
		}
	}
	return out
}

// A standard catalog with six controls exercises every branch of the posture
// ladder within one SSP: not-applicable and planned are muted, an undeclared or
// declared-but-unproven control raises attention, satisfying evidence wins over a
// declared status, and a control outside the SSP's profile is out-of-scope.
func (suite *LineagePostureSuite) TestPostureOverlayForSelectedSSP() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	catalog := relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls: []relational.Control{
			{CatalogID: catID, ID: "na", Title: "Not Applicable"},
			{CatalogID: catID, ID: "planned", Title: "Planned"},
			{CatalogID: catID, ID: "impl", Title: "Declared implemented, no evidence"},
			{CatalogID: catID, ID: "none", Title: "In profile, no status"},
			{CatalogID: catID, ID: "ev", Title: "Declared implemented, has evidence"},
			{CatalogID: catID, ID: "out", Title: "Not in profile"},
		},
	}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)

	// Profile resolves every control EXCEPT "out"; bound to one SSP.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	for _, cid := range []string{"na", "planned", "impl", "none", "ev"} {
		suite.Require().NoError(suite.DB.Exec(
			"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
			profileID, catID, cid).Error)
	}

	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		Metadata:  relational.Metadata{Title: "S", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		sspID, profileID).Error)

	// Control implementation with an implemented-requirement per in-profile control.
	ci := relational.ControlImplementation{Description: "ci", SystemSecurityPlanId: sspID}
	suite.Require().NoError(suite.DB.Create(&ci).Error)
	mkIR := func(controlID string) uuid.UUID {
		ir := relational.ImplementedRequirement{ControlId: controlID, ControlImplementationId: *ci.ID}
		suite.Require().NoError(suite.DB.Create(&ir).Error)
		return *ir.ID
	}
	naIR := mkIR("na")
	plannedIR := mkIR("planned")
	implIR := mkIR("impl")
	mkIR("none") // bare requirement: in profile, no declared status
	evIR := mkIR("ev")

	// A by-component carries the declared implementation status.
	mkBC := func(irID uuid.UUID, state relational.ImplementationStatusState) {
		pt := "implemented_requirements"
		bcID := uuid.New()
		suite.Require().NoError(suite.DB.Create(&relational.ByComponent{
			UUIDModel:            relational.UUIDModel{ID: &bcID},
			ParentID:             &irID,
			ParentType:           &pt,
			ComponentUUID:        uuid.New(),
			ImplementationStatus: datatypes.NewJSONType(relational.ImplementationStatus{State: state}),
		}).Error)
	}
	mkBC(naIR, relational.ImplementationStatusNotApplicable)
	mkBC(plannedIR, relational.ImplementationStatusPlanned)
	mkBC(implIR, relational.ImplementationStatusImplemented)
	mkBC(evIR, relational.ImplementationStatusImplemented) // evidence must still win

	// Satisfying evidence for "ev" via a label filter.
	f := relational.Filter{
		Name: "ev-filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "ev"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, catID, "ev").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "ev-1",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'ev') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'ev')", evID).Error)

	// --- Single-SSP overlay: each control carries its posture. ---
	nodes := byControlID(suite.childrenOf("catalog:"+catID.String(), sspID.String()))
	suite.Require().Len(nodes, 6)

	expect := func(controlID, posture, impl string, inProfile bool) {
		n := nodes[controlID]
		suite.Require().NotNil(n.SSP, "control %q should carry an SSP overlay", controlID)
		suite.Equalf(posture, n.SSP.Posture, "control %q posture", controlID)
		suite.Equalf(inProfile, n.SSP.InProfile, "control %q inProfile", controlID)
		suite.Equalf(impl, n.SSP.ImplementationStatus, "control %q implementationStatus", controlID)
	}
	expect("na", PostureNotApplicable, "not-applicable", true)
	expect("planned", PosturePlanned, "planned", true)
	expect("impl", PostureAttention, "implemented", true)
	expect("none", PostureAttention, "", true)
	expect("ev", PostureSatisfied, "implemented", true) // evidence beats declared status
	expect("out", PostureOutOfScope, "", false)

	suite.Equal(relational.EvidenceStatusSatisfied, nodes["ev"].SSP.EvidenceStatus)

	// --- Structural tally: the catalog root sums its controls' postures. ---
	var stdRoot *LineageNode
	for _, r := range suite.roots(sspID.String()) {
		if r.CatalogID == catID.String() {
			r := r
			stdRoot = &r
		}
	}
	suite.Require().NotNil(stdRoot)
	suite.Require().NotNil(stdRoot.PostureCounts)
	suite.Equal(1, stdRoot.PostureCounts.Satisfied)
	suite.Equal(1, stdRoot.PostureCounts.NotApplicable)
	suite.Equal(1, stdRoot.PostureCounts.Planned)
	suite.Equal(2, stdRoot.PostureCounts.Attention)
	suite.Equal(1, stdRoot.PostureCounts.OutOfScope)
	suite.Equal(0, stdRoot.PostureCounts.NotSatisfied)

	// --- Global view: cross-SSP breakdown, no per-SSP overlay. ---
	global := byControlID(suite.childrenOf("catalog:"+catID.String(), ""))
	suite.Require().NotNil(global["na"].SSPBreakdown)
	suite.Nil(global["na"].SSP, "global view must not carry a single-SSP overlay")
	suite.Equal(1, global["na"].SSPBreakdown.TotalSSPs)
	suite.Equal(1, global["na"].SSPBreakdown.NotApplicable)
	suite.Equal(1, global["ev"].SSPBreakdown.Satisfied)
	suite.Equal(1, global["out"].SSPBreakdown.OutOfScope)
	suite.Equal(1, global["impl"].SSPBreakdown.Attention)
}

// A standard control implemented indirectly — internal/operational control ->
// (implements) -> standard — inherits the operational control's SSP coverage. The
// standard is in NO SSP profile itself, but because its implementer is in the SSP
// and satisfied, the standard's posture rolls up to satisfied (not out-of-scope).
func (suite *LineagePostureSuite) TestPostureInheritsThroughControlLinks() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	stdCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &stdCat},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Standard", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: stdCat, ID: "std-1", Title: "Abstract requirement"}},
	}).Error)

	// An internal (operational) catalog whose control implements the standard.
	intCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &intCat},
		CatalogType: relational.CatalogTypeInternal,
		Metadata:    relational.Metadata{Title: "Internal", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: intCat, ID: "int-1", Title: "Concrete control"}},
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.ControlLink{
		SourceCatalogID:  intCat,
		SourceControlID:  "int-1",
		TargetCatalogID:  stdCat,
		TargetControlID:  "std-1",
		RelationshipType: relational.RelationshipImplements,
	}).Error)

	// The SSP's profile resolves ONLY the internal control, not the standard.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID, intCat, "int-1").Error)
	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		Metadata:  relational.Metadata{Title: "S", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		sspID, profileID).Error)

	// Satisfying evidence attached to the internal control.
	f := relational.Filter{
		Name: "int-filter",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "int"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, intCat, "int-1").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "int-ev",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'int') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'int')", evID).Error)

	// Single-SSP: the standard control inherits satisfied from its implementer even
	// though the standard itself is not in the SSP's profile.
	std := byControlID(suite.childrenOf("catalog:"+stdCat.String(), sspID.String()))["std-1"]
	suite.Require().NotNil(std.SSP)
	suite.Equal(PostureSatisfied, std.SSP.Posture, "standard should inherit its implementer's coverage")
	suite.True(std.SSP.InProfile, "standard is in scope via its implementer")

	// Global: the standard's breakdown shows the SSP as satisfied, not out-of-scope.
	stdGlobal := byControlID(suite.childrenOf("catalog:"+stdCat.String(), ""))["std-1"]
	suite.Require().NotNil(stdGlobal.SSPBreakdown)
	suite.Equal(1, stdGlobal.SSPBreakdown.Satisfied)
	suite.Equal(0, stdGlobal.SSPBreakdown.OutOfScope)
}

// A policy control carried by an SSP's profile is assessed exactly like a control;
// a documentation policy that no profile carries and nothing implements gets no
// posture overlay at all (stays a plain structural node).
func (suite *LineagePostureSuite) TestPolicyInProfileBehavesLikeControl() {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	polCat := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &polCat},
		CatalogType: relational.CatalogTypePolicy,
		Metadata:    relational.Metadata{Title: "Policy", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls: []relational.Control{
			{CatalogID: polCat, ID: "pol-scoped", Title: "Carried by a profile"},
			{CatalogID: polCat, ID: "pol-doc", Title: "Documentation only"},
		},
	}).Error)

	// A profile/SSP that resolves ONLY the first policy control.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID, polCat, "pol-scoped").Error)
	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		Metadata:  relational.Metadata{Title: "S", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		sspID, profileID).Error)

	nodes := byControlID(suite.childrenOf("catalog:"+polCat.String(), sspID.String()))

	// The profiled policy control is assessed like a control (attention: in scope,
	// no evidence, no declared status).
	scoped := nodes["pol-scoped"]
	suite.Require().NotNil(scoped.SSP, "a profiled policy control should carry a posture overlay")
	suite.Equal(PostureAttention, scoped.SSP.Posture)
	suite.True(scoped.SSP.InProfile)

	// The documentation-only policy control carries no overlay.
	suite.Nil(nodes["pol-doc"].SSP, "a documentation policy control should have no posture overlay")
}

// With a single SSP selected, a structural node's posture bar (PostureCounts) sums
// its descendant LEAF controls — including out-of-scope leaves — the same way the
// global cross-SSP breakdown does, rather than counting the abstract parent once.
func (suite *LineagePostureSuite) TestSingleSSPPostureCountsSumLeaves() {
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
			{CatalogID: intCat, ID: "op-in", Title: "In profile"},
			{CatalogID: intCat, ID: "op-out", Title: "Out of profile"},
		},
	}).Error)
	for _, op := range []string{"op-in", "op-out"} {
		suite.Require().NoError(suite.DB.Create(&relational.ControlLink{
			SourceCatalogID: intCat, SourceControlID: op,
			TargetCatalogID: stdCat, TargetControlID: "std-1",
			RelationshipType: relational.RelationshipImplements,
		}).Error)
	}

	// The profile resolves op-in only; op-out is out of scope for this plan.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID, intCat, "op-in").Error)
	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
		Metadata:  relational.Metadata{Title: "S", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		sspID, profileID).Error)

	// op-in has satisfying evidence.
	f := relational.Filter{
		Name: "f",
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "in"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, intCat, "op-in").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "ev",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'in') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'in')", evID).Error)

	// The standard catalog's bar sums its two leaves: op-in satisfied, op-out
	// out-of-scope — NOT the abstract std-1 counted once.
	var stdRoot *LineageNode
	for _, r := range suite.roots(sspID.String()) {
		if r.CatalogID == stdCat.String() {
			r := r
			stdRoot = &r
		}
	}
	suite.Require().NotNil(stdRoot)
	suite.Require().NotNil(stdRoot.PostureCounts, "structural node should carry a posture bar")
	suite.Equal(1, stdRoot.PostureCounts.Satisfied, "op-in")
	suite.Equal(1, stdRoot.PostureCounts.OutOfScope, "op-out is summed as out-of-scope")
	suite.Equal(0, stdRoot.PostureCounts.NotSatisfied+stdRoot.PostureCounts.NotApplicable+
		stdRoot.PostureCounts.Planned+stdRoot.PostureCounts.Attention)

	// The abstract std-1 CONTROL node carries the same bar in single-SSP as its
	// catalog (and as its global SSPBreakdown) — a control's bar is consistent
	// whether or not an SSP is filtered.
	std := byControlID(suite.childrenOf("catalog:"+stdCat.String(), sspID.String()))["std-1"]
	suite.Require().NotNil(std.PostureCounts, "control node should carry a posture bar in single-SSP")
	suite.Equal(1, std.PostureCounts.Satisfied)
	suite.Equal(1, std.PostureCounts.OutOfScope)
}
