//go:build integration

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/leverage"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

func TestLineageLeverage(t *testing.T) {
	suite.Run(t, new(LineageLeverageSuite))
}

type LineageLeverageSuite struct {
	tests.IntegrationTestSuite
}

// inheritedSeed carries the ids of a single-control, single-downstream leverage
// scenario so a test can mutate one part (drift the link, add evidence, drop a
// satisfied row) and re-query.
type inheritedSeed struct {
	catID         uuid.UUID
	controlID     string
	downstreamSSP uuid.UUID
	upstreamSSP   uuid.UUID
	offeringID    uuid.UUID
	linkID        uuid.UUID
	byComponentID uuid.UUID
	providedUUID  uuid.UUID
	resp1, resp2  uuid.UUID
	sat2ID        uuid.UUID
}

// seedInherited builds an upstream offering with two responsibilities, a downstream SSP
// whose profile carries control AC-2, and an active leverage link with both
// responsibilities satisfied — the credit-earning baseline.
func (suite *LineageLeverageSuite) seedInherited() inheritedSeed {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Catalog{
		UUIDModel:   relational.UUIDModel{ID: &catID},
		CatalogType: relational.CatalogTypeStandard,
		Metadata:    relational.Metadata{Title: "Std", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
		Controls:    []relational.Control{{CatalogID: catID, ID: "AC-2", Title: "Account Management"}},
	}).Error)

	// Downstream SSP whose profile resolves AC-2.
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		profileID, catID, "AC-2").Error)
	downstreamSSP := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &downstreamSSP},
		Metadata:  relational.Metadata{Title: "Downstream SSP", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)",
		downstreamSSP, profileID).Error)

	// Upstream SSP + published offering + provided capability with two responsibilities.
	upstreamSSP := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &upstreamSSP},
		Metadata:  relational.Metadata{Title: "Platform SSP", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)
	offeringID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SSPExportOffering{
		UUIDModel: relational.UUIDModel{ID: &offeringID},
		SSPID:     upstreamSSP,
		Title:     "Managed Postgres",
		Version:   2,
		Status:    relational.SSPExportOfferingStatusPublished,
	}).Error)

	exportID := uuid.New()
	providedUUID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.ProvidedControlImplementation{
		UUIDModel:   relational.UUIDModel{ID: &providedUUID},
		Description: "provided",
		ExportId:    exportID,
	}).Error)
	resp1, resp2 := uuid.New(), uuid.New()
	for _, r := range []uuid.UUID{resp1, resp2} {
		r := r
		suite.Require().NoError(suite.DB.Create(&relational.ControlImplementationResponsibility{
			UUIDModel:    relational.UUIDModel{ID: &r},
			Description:  "resp " + r.String(),
			ProvidedUuid: providedUUID,
			ExportId:     exportID,
		}).Error)
	}

	// Downstream inherited row + active link + satisfied rows for BOTH responsibilities.
	byComponentID := uuid.New()
	inheritedUUID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.InheritedControlImplementation{
		UUIDModel:     relational.UUIDModel{ID: &inheritedUUID},
		ProvidedUuid:  providedUUID,
		Description:   "inherited",
		ByComponentId: byComponentID,
	}).Error)

	linkID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SSPLeverageLink{
		UUIDModel:       relational.UUIDModel{ID: &linkID},
		DownstreamSSPID: downstreamSSP,
		UpstreamSSPID:   upstreamSSP,
		OfferingID:      offeringID,
		OfferingVersion: 2,
		ControlID:       "AC-2",
		ProvidedUUID:    providedUUID,
		InheritedUUID:   inheritedUUID,
		Satisfaction:    relational.SSPLeverageSatisfactionFull,
		Status:          relational.SSPLeverageStatusActive,
	}).Error)

	sat1ID, sat2ID := uuid.New(), uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SatisfiedControlImplementationResponsibility{
		UUIDModel:          relational.UUIDModel{ID: &sat1ID},
		ResponsibilityUuid: resp1,
		Description:        "sat1",
		ByComponentId:      byComponentID,
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.SatisfiedControlImplementationResponsibility{
		UUIDModel:          relational.UUIDModel{ID: &sat2ID},
		ResponsibilityUuid: resp2,
		Description:        "sat2",
		ByComponentId:      byComponentID,
	}).Error)

	return inheritedSeed{
		catID: catID, controlID: "AC-2", downstreamSSP: downstreamSSP, upstreamSSP: upstreamSSP,
		offeringID: offeringID, linkID: linkID, byComponentID: byComponentID, providedUUID: providedUUID,
		resp1: resp1, resp2: resp2, sat2ID: sat2ID,
	}
}

func (suite *LineageLeverageSuite) get(handlerCall func(echo.Context) error, path, key, sspID string, out any) {
	url := path
	if sspID != "" {
		url += "?sspId=" + sspID
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	if key != "" {
		ctx.SetParamNames("key")
		ctx.SetParamValues(key)
	}
	suite.Require().NoError(handlerCall(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), out))
}

func (suite *LineageLeverageSuite) handler() *LineageHandler {
	return NewLineageHandler(zap.NewNop().Sugar(), suite.DB)
}

func (suite *LineageLeverageSuite) controlNode(catID, sspID string) LineageNode {
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	suite.get(suite.handler().Children, "/x", "catalog:"+catID, sspID, &resp)
	for _, n := range resp.Data {
		if n.ControlID == "AC-2" {
			return n
		}
	}
	suite.Require().Fail("AC-2 control node not found")
	return LineageNode{}
}

func (suite *LineageLeverageSuite) catalogRoot(catID, sspID string) LineageNode {
	var resp struct {
		Data []LineageNode `json:"data"`
	}
	suite.get(suite.handler().Roots, "/x", "", sspID, &resp)
	for _, n := range resp.Data {
		if n.CatalogID == catID {
			return n
		}
	}
	suite.Require().Fail("catalog root not found")
	return LineageNode{}
}

// TestInheritedCreditRootsAndDrawer covers the credit-earning baseline: the control
// reads inherited in scoped and global rollups, the /ssps drawer, and the new
// /leverage drawer (Contract C shape).
func (suite *LineageLeverageSuite) TestInheritedCreditRootsAndDrawer() {
	s := suite.seedInherited()
	catKey := s.catID.String()
	controlKey := "control:" + s.catID.String() + "/AC-2"

	// (1) Scoped roots: inherited posture + counts + percent math.
	root := suite.catalogRoot(catKey, s.downstreamSSP.String())
	suite.Require().NotNil(root.PostureCounts)
	suite.Equal(1, root.PostureCounts.Inherited)
	suite.Equal(1, root.Compliance.Inherited)
	suite.Equal(0, root.Compliance.Unknown)
	suite.Equal(1, root.Compliance.TotalControls)
	suite.Equal(float64(100), root.Compliance.CompliancePercent)
	suite.Equal(float64(100), root.Compliance.AssessedPercent)

	ctrl := suite.controlNode(catKey, s.downstreamSSP.String())
	suite.Require().NotNil(ctrl.SSP)
	suite.Equal(PostureInherited, ctrl.SSP.Posture)
	suite.Require().NotNil(ctrl.SSP.Leverage)
	suite.Equal("active", ctrl.SSP.Leverage.Status)
	suite.Equal("full", ctrl.SSP.Leverage.Satisfaction)
	suite.Equal(2, ctrl.SSP.Leverage.TotalResponsibilities)
	suite.Equal(0, ctrl.SSP.Leverage.OutstandingCount)

	// (2) Global roots: cross-SSP breakdown counts inherited.
	globalRoot := suite.catalogRoot(catKey, "")
	suite.Require().NotNil(globalRoot.SSPBreakdown)
	suite.Equal(1, globalRoot.SSPBreakdown.Inherited)
	suite.Equal(1, globalRoot.Compliance.Inherited)

	// (3) /ssps drawer: the downstream row is inherited + carries the leverage badge.
	var sspRows struct {
		Data []LineageSSPRow `json:"data"`
	}
	suite.get(suite.handler().SSPDetail, "/x", controlKey, "", &sspRows)
	var downstreamRow *LineageSSPRow
	for i := range sspRows.Data {
		if sspRows.Data[i].SSPID == s.downstreamSSP.String() {
			downstreamRow = &sspRows.Data[i]
		}
	}
	suite.Require().NotNil(downstreamRow)
	suite.Equal(PostureInherited, downstreamRow.Posture)
	suite.Require().NotNil(downstreamRow.Leverage)
	suite.Equal("active", downstreamRow.Leverage.Status)

	// (4) /leverage drawer: Contract C shape with upstream title + responsibility posture.
	var lev struct {
		Data []LineageLeverageRow `json:"data"`
	}
	suite.get(suite.handler().LeverageDetail, "/x", controlKey, "", &lev)
	suite.Require().Len(lev.Data, 1)
	row := lev.Data[0]
	suite.Equal(s.downstreamSSP.String(), row.SSPID)
	suite.Equal("Downstream SSP", row.SSPTitle)
	suite.Require().Len(row.Links, 1)
	link := row.Links[0]
	suite.Equal("AC-2", link.ControlID)
	suite.Equal(s.providedUUID, link.ProvidedUuid)
	suite.Equal(s.upstreamSSP, link.InheritedFrom.UpstreamSSPID)
	suite.Equal("Platform SSP", link.InheritedFrom.UpstreamSSPTitle)
	suite.Equal("Managed Postgres", link.InheritedFrom.OfferingTitle)
	suite.Equal(2, link.InheritedFrom.OfferingVersion)
	suite.Equal(relational.SSPLeverageSatisfactionFull, link.Satisfaction)
	suite.Equal(relational.SSPLeverageStatusActive, link.Status)
	suite.Require().Len(link.Responsibilities, 2)
	suite.Len(link.OutstandingResponsibilities, 0)
	suite.Require().NotNil(link.ResponsibilityPosture)
	suite.Contains(link.ResponsibilityPosture, s.resp1)
	suite.Contains(link.ResponsibilityPosture, s.resp2)

	// sspId filter narrows to the one downstream SSP (and non-matching filter empties).
	var filtered struct {
		Data []LineageLeverageRow `json:"data"`
	}
	suite.get(suite.handler().LeverageDetail, "/x", controlKey, s.downstreamSSP.String(), &filtered)
	suite.Require().Len(filtered.Data, 1)
}

// TestInheritedDriftDropsCredit: a drifted link earns no credit and reads attention,
// but the leverage badge still surfaces with the drifted status and its open drift risk.
func (suite *LineageLeverageSuite) TestInheritedDriftDropsCredit() {
	s := suite.seedInherited()
	suite.Require().NoError(suite.DB.Model(&relational.SSPLeverageLink{}).
		Where("id = ?", s.linkID).Update("status", relational.SSPLeverageStatusDrifted).Error)
	// An open drift risk keyed the same way the projection reads it.
	driftRiskID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&riskrel.Risk{
		UUIDModel: relational.UUIDModel{ID: &driftRiskID},
		SSPID:     s.downstreamSSP,
		Title:     "drift",
		Status:    string(riskrel.RiskStatusOpen),
		DedupeKey: leverage.DriftDedupeKey(s.linkID),
	}).Error)

	catKey := s.catID.String()
	root := suite.catalogRoot(catKey, s.downstreamSSP.String())
	suite.Require().NotNil(root.PostureCounts)
	suite.Equal(0, root.PostureCounts.Inherited)
	suite.Equal(1, root.PostureCounts.Attention)
	suite.Equal(0, root.Compliance.Inherited)
	suite.Equal(1, root.Compliance.Unknown)

	ctrl := suite.controlNode(catKey, s.downstreamSSP.String())
	suite.Require().NotNil(ctrl.SSP)
	suite.Equal(PostureAttention, ctrl.SSP.Posture)
	suite.Require().NotNil(ctrl.SSP.Leverage)
	suite.Equal("drifted", ctrl.SSP.Leverage.Status)

	// The /leverage drawer surfaces the open drift risk id.
	var lev struct {
		Data []LineageLeverageRow `json:"data"`
	}
	suite.get(suite.handler().LeverageDetail, "/x", "control:"+s.catID.String()+"/AC-2", "", &lev)
	suite.Require().Len(lev.Data, 1)
	suite.Require().Len(lev.Data[0].Links, 1)
	suite.Require().NotNil(lev.Data[0].Links[0].DriftRiskID)
	suite.Equal(driftRiskID, *lev.Data[0].Links[0].DriftRiskID)
}

// TestInheritedEvidenceWins: decisive downstream evidence overrides inherited credit.
func (suite *LineageLeverageSuite) TestInheritedEvidenceWins() {
	s := suite.seedInherited()
	now := time.Now().UTC()

	// An SSP-scoped filter on AC-2 with a not-satisfied observation.
	f := relational.Filter{
		Name:  "ac2-filter",
		SSPID: &s.downstreamSSP,
		Filter: datatypes.NewJSONType(labelfilter.Filter{
			Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{Label: "ctrl", Operator: "=", Value: "ac-2"}},
		}),
	}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO filter_controls (filter_id, control_catalog_id, control_id) VALUES (?, ?, ?)",
		f.ID, s.catID, "AC-2").Error)
	evID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evID},
		UUID:      uuid.New(),
		Title:     "ev",
		Start:     now, End: now, Expires: &now,
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied", Reason: "auto"}),
	}).Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO labels (name, value) VALUES ('ctrl', 'ac-2') ON CONFLICT DO NOTHING").Error)
	suite.Require().NoError(suite.DB.Exec(
		"INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, 'ctrl', 'ac-2')", evID).Error)

	ctrl := suite.controlNode(s.catID.String(), s.downstreamSSP.String())
	suite.Require().NotNil(ctrl.SSP)
	suite.Equal(PostureNotSatisfied, ctrl.SSP.Posture)
	// Leverage badge is still attached (links exist), even though evidence won.
	suite.Require().NotNil(ctrl.SSP.Leverage)

	root := suite.catalogRoot(s.catID.String(), s.downstreamSSP.String())
	suite.Equal(0, root.Compliance.Inherited)
	suite.Equal(1, root.Compliance.NotSatisfied)
}

// TestInheritedPartialDropsCredit: dropping a satisfied row makes live derivation
// partial, so no credit is granted even though the stored column was never rewritten.
func (suite *LineageLeverageSuite) TestInheritedPartialDropsCredit() {
	s := suite.seedInherited()
	// Delete one satisfied row -> only 1 of 2 responsibilities covered -> partial.
	suite.Require().NoError(suite.DB.Delete(&relational.SatisfiedControlImplementationResponsibility{}, "id = ?", s.sat2ID).Error)

	ctrl := suite.controlNode(s.catID.String(), s.downstreamSSP.String())
	suite.Require().NotNil(ctrl.SSP)
	suite.Equal(PostureAttention, ctrl.SSP.Posture)
	suite.Require().NotNil(ctrl.SSP.Leverage)
	suite.Equal("partial", ctrl.SSP.Leverage.Satisfaction)
	suite.Equal(1, ctrl.SSP.Leverage.OutstandingCount)

	root := suite.catalogRoot(s.catID.String(), s.downstreamSSP.String())
	suite.Equal(0, root.Compliance.Inherited)
	suite.Equal(1, root.Compliance.Unknown)
}
