//go:build integration

package oscal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// profileLeverageSeed carries the ids of a compliance-progress leverage scenario.
type profileLeverageSeed struct {
	profileID     uuid.UUID
	downstreamSSP uuid.UUID
	upstreamSSP   uuid.UUID
	offeringID    uuid.UUID
}

// seedProfileLeverage creates a profile carrying AC-2, a downstream SSP, and an active
// leverage link inheriting AC-2 from an upstream "Platform SSP" offering with two
// responsibilities. satisfyBoth controls whether both responsibilities are satisfied
// (credit) or only one (partial, no credit).
func (suite *ProfileIntegrationSuite) seedProfileLeverage(satisfyBoth bool) profileLeverageSeed {
	suite.Require().NoError(suite.Migrator.Refresh())
	now := time.Now().UTC()

	catID := uuid.New()
	control := relational.Control{CatalogID: catID, ID: "AC-2", Title: "Account Management"}
	suite.Require().NoError(suite.DB.Create(&control).Error)

	profileID := uuid.New()
	profile := relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "P", Version: "1.0.0", OscalVersion: "1.1.3"},
	}
	suite.Require().NoError(suite.DB.Create(&profile).Error)
	suite.Require().NoError(suite.DB.Model(&profile).Association("Controls").Append(&control))

	downstreamSSP := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &downstreamSSP},
		Metadata:  relational.Metadata{Title: "Downstream SSP", Version: "1.0.0", OscalVersion: "1.1.3", LastModified: &now},
	}).Error)

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

	toSatisfy := []uuid.UUID{resp1, resp2}
	if !satisfyBoth {
		toSatisfy = []uuid.UUID{resp1}
	}
	for _, r := range toSatisfy {
		id := uuid.New()
		suite.Require().NoError(suite.DB.Create(&relational.SatisfiedControlImplementationResponsibility{
			UUIDModel:          relational.UUIDModel{ID: &id},
			ResponsibilityUuid: r,
			Description:        "sat",
			ByComponentId:      byComponentID,
		}).Error)
	}

	return profileLeverageSeed{profileID: profileID, downstreamSSP: downstreamSSP, upstreamSSP: upstreamSSP, offeringID: offeringID}
}

func (suite *ProfileIntegrationSuite) complianceProgress(profileID, sspID string) ProfileComplianceProgress {
	url := "/profiles/" + profileID + "/compliance-progress"
	if sspID != "" {
		url += "?sspId=" + sspID
	}
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(profileID)
	suite.Require().NoError(NewProfileHandler(zap.NewNop().Sugar(), suite.DB).ComplianceProgress(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data ProfileComplianceProgress `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// TestComplianceProgressInheritedCredit: with sspId, an inherited control lands in the
// inherited bucket, carries the leverage badge, and counts as compliant + assessed.
func (suite *ProfileIntegrationSuite) TestComplianceProgressInheritedCredit() {
	s := suite.seedProfileLeverage(true)
	data := suite.complianceProgress(s.profileID.String(), s.downstreamSSP.String())

	suite.Equal(1, data.Summary.TotalControls)
	suite.Equal(1, data.Summary.Inherited)
	suite.Equal(0, data.Summary.Satisfied)
	suite.Equal(0, data.Summary.NotSatisfied)
	suite.Equal(0, data.Summary.Unknown)
	suite.Equal(100, data.Summary.CompliancePct)
	suite.Equal(100, data.Summary.AssessedPct)

	suite.Require().Len(data.Controls, 1)
	ctrl := data.Controls[0]
	suite.Equal("inherited", ctrl.ComputedStatus)
	suite.Require().NotNil(ctrl.Leverage)
	suite.True(ctrl.Leverage.Inherited)
	suite.Equal(relational.SSPLeverageSatisfactionFull, ctrl.Leverage.Satisfaction)
	suite.Equal(relational.SSPLeverageStatusActive, ctrl.Leverage.Status)
	suite.Equal(1, ctrl.Leverage.Links)
	suite.Equal(2, ctrl.Leverage.TotalResponsibilities)
	suite.Equal(0, ctrl.Leverage.OutstandingCount)
	suite.Require().Len(ctrl.Leverage.InheritedFrom, 1)
	suite.Equal(s.upstreamSSP, ctrl.Leverage.InheritedFrom[0].UpstreamSSPID)
	suite.Equal("Platform SSP", ctrl.Leverage.InheritedFrom[0].UpstreamSSPTitle)
	suite.Equal("Managed Postgres", ctrl.Leverage.InheritedFrom[0].OfferingTitle)
	suite.Equal(2, ctrl.Leverage.InheritedFrom[0].OfferingVersion)
}

// TestComplianceProgressPartialNoCredit: a partially-satisfied link earns no credit —
// the control stays unknown but still surfaces its partial leverage badge.
func (suite *ProfileIntegrationSuite) TestComplianceProgressPartialNoCredit() {
	s := suite.seedProfileLeverage(false)
	data := suite.complianceProgress(s.profileID.String(), s.downstreamSSP.String())

	suite.Equal(0, data.Summary.Inherited)
	suite.Equal(1, data.Summary.Unknown)

	suite.Require().Len(data.Controls, 1)
	ctrl := data.Controls[0]
	suite.Equal("unknown", ctrl.ComputedStatus)
	suite.Require().NotNil(ctrl.Leverage)
	suite.False(ctrl.Leverage.Inherited)
	suite.Equal(relational.SSPLeverageSatisfactionPartial, ctrl.Leverage.Satisfaction)
	suite.Equal(1, ctrl.Leverage.OutstandingCount)
}

// TestComplianceProgressNoSSPNoLeverage: without sspId, no leverage payloads are
// emitted and inherited stays 0.
func (suite *ProfileIntegrationSuite) TestComplianceProgressNoSSPNoLeverage() {
	s := suite.seedProfileLeverage(true)
	data := suite.complianceProgress(s.profileID.String(), "")

	suite.Equal(0, data.Summary.Inherited)
	suite.Require().Len(data.Controls, 1)
	suite.Nil(data.Controls[0].Leverage)
}
