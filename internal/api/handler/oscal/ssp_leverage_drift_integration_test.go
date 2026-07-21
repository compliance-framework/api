//go:build integration

package oscal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// LeverageDriftIntegrationSuite exercises BCH-1341's full drift pipeline against real
// Postgres: the ticket's own Tests bullet (publish v1 -> subscribe -> downgrade a
// provided status -> re-sync -> link drifted + inherited-revoked risk + notification;
// re-attest -> cleared), plus the deprecate/revoke and leveraged-auth-lapse triggers,
// idempotency, and the AC #3 isolation requirement (no upstream risk/evidence exposed
// downstream).
type LeverageDriftIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestLeverageDriftIntegrationSuite(t *testing.T) {
	suite.Run(t, new(LeverageDriftIntegrationSuite))
}

func (suite *LeverageDriftIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

// driftFixture is the minimal real-schema graph every test in this suite needs: an
// upstream SSP with one published offering item backed by a real ByComponent (so the
// ImplementationStatus-downgrade trigger has something live to read), and a downstream
// SSP with the scaffolding Subscribe requires (ControlImplementation/SystemImplementation).
type driftFixture struct {
	upstreamSSPID   uuid.UUID
	downstreamSSPID uuid.UUID
	offeringID      uuid.UUID
	itemID          uuid.UUID
	byComponentID   uuid.UUID
	providedID      uuid.UUID
	respID          uuid.UUID
}

// driftStatementID is the statement the fixture's leverageable capability is exported from.
// Subscribe rejects a statementless offering item with 422, so the fixture's exporting
// by-component is anchored on a real statement, as the model now requires everywhere.
const driftStatementID = "ac-1_smt.a"

func seedDriftFixture(suite *LeverageDriftIntegrationSuite) driftFixture {
	db := suite.DB

	upstreamSSP := relational.SystemSecurityPlan{}
	suite.Require().NoError(db.Create(&upstreamSSP).Error)

	upstreamImpl := relational.ControlImplementation{SystemSecurityPlanId: *upstreamSSP.ID}
	suite.Require().NoError(db.Create(&upstreamImpl).Error)
	requirement := relational.ImplementedRequirement{ControlImplementationId: *upstreamImpl.ID, ControlId: "ac-1"}
	suite.Require().NoError(db.Create(&requirement).Error)
	statement := relational.Statement{ImplementedRequirementId: *requirement.ID, StatementId: driftStatementID}
	suite.Require().NoError(db.Create(&statement).Error)

	statementsType := "statements"
	byComponent := relational.ByComponent{
		ParentID:             statement.ID,
		ParentType:           &statementsType,
		ImplementationStatus: datatypes.NewJSONType(relational.ImplementationStatus{State: relational.ImplementationStatusImplemented}),
	}
	suite.Require().NoError(db.Create(&byComponent).Error)

	export := relational.Export{ByComponentId: *byComponent.ID}
	suite.Require().NoError(db.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided"}
	suite.Require().NoError(db.Create(&provided).Error)

	resp := relational.ControlImplementationResponsibility{ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "responsibility"}
	suite.Require().NoError(db.Create(&resp).Error)

	offering := relational.SSPExportOffering{SSPID: *upstreamSSP.ID, Title: "Offering", Status: relational.SSPExportOfferingStatusDraft}
	suite.Require().NoError(db.Create(&offering).Error)

	statementID := driftStatementID
	item := relational.SSPExportOfferingItem{
		OfferingID: *offering.ID, ControlID: "ac-1", StatementID: &statementID,
		ComponentUUID: byComponent.ComponentUUID, ProvidedUUID: *provided.ID,
	}
	suite.Require().NoError(db.Create(&item).Error)

	downstreamSSP := relational.SystemSecurityPlan{}
	suite.Require().NoError(db.Create(&downstreamSSP).Error)
	suite.Require().NoError(db.Create(&relational.ControlImplementation{SystemSecurityPlanId: *downstreamSSP.ID}).Error)
	suite.Require().NoError(db.Create(&relational.SystemImplementation{SystemSecurityPlanId: *downstreamSSP.ID}).Error)

	fx := driftFixture{
		upstreamSSPID: *upstreamSSP.ID, downstreamSSPID: *downstreamSSP.ID,
		offeringID: *offering.ID, itemID: *item.ID, byComponentID: *byComponent.ID,
		providedID: *provided.ID, respID: *resp.ID,
	}

	// Publish v1 for real (rather than seeding Status=published/Version=1 directly) so
	// ContentHash is genuinely established — the ticket's own flow starts with "publish
	// v1", and skipping this step would make the *next* Publish call look like a content
	// change (empty ContentHash != any computed hash) even when nothing actually changed.
	publishResp := suite.publish(fx.upstreamSSPID, fx.offeringID, nil)
	suite.Require().Equal(http.StatusOK, publishResp.Code)

	return fx
}

func (suite *LeverageDriftIntegrationSuite) subscribe(fx driftFixture) relational.SSPLeverageLink {
	pdp := &stubPDP{allow: true}
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), suite.DB, pdp, authz.FailClosed)
	body := subscribeBody(fx.downstreamSSPID, fx.itemID, fx.respID)
	ctx, _, rec := newSubscribeRequestContext(fx.offeringID, body)
	suite.Require().NoError(h.Subscribe(ctx))
	suite.Require().Equal(http.StatusCreated, rec.Code)

	var link relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.Where("downstream_ssp_id = ? AND offering_id = ?", fx.downstreamSSPID, fx.offeringID).First(&link).Error)
	return link
}

func (suite *LeverageDriftIntegrationSuite) publish(sspID, offeringID uuid.UUID, jobEnqueuer SSPJobEnqueuer) *httptest.ResponseRecorder {
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), suite.DB, jobEnqueuer)
	ctx, rec := newPublishRequestContext(sspID, offeringID)
	suite.Require().NoError(h.Publish(ctx))
	return rec
}

// TestFullDriftAndReAttestFlow is the ticket's own Tests bullet, end to end: publish v1
// -> subscribe -> downgrade a provided status -> re-sync -> link drifted +
// inherited-revoked risk + notification; re-attest -> cleared.
func (suite *LeverageDriftIntegrationSuite) TestFullDriftAndReAttestFlow() {
	fx := seedDriftFixture(suite)
	link := suite.subscribe(fx)
	suite.Equal(relational.SSPLeverageStatusActive, link.Status)
	suite.Equal(1, link.OfferingVersion)

	spy := &spyJobEnqueuer{}
	resp := suite.publish(fx.upstreamSSPID, fx.offeringID, spy)
	suite.Equal(http.StatusOK, resp.Code)
	suite.Empty(spy.calls, "re-publishing with no content change must not drift anything")

	// Downgrade the backing component's status, then re-sync (re-publish).
	suite.Require().NoError(suite.DB.Model(&relational.ByComponent{}).Where("id = ?", fx.byComponentID).Update(
		"implementation_status", datatypes.NewJSONType(relational.ImplementationStatus{State: relational.ImplementationStatusPlanned}),
	).Error)

	resp = suite.publish(fx.upstreamSSPID, fx.offeringID, spy)
	suite.Equal(http.StatusOK, resp.Code)

	var reloadedLink relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&reloadedLink, "id = ?", link.ID).Error)
	suite.Equal(relational.SSPLeverageStatusDrifted, reloadedLink.Status)

	var driftRisk risks.Risk
	suite.Require().NoError(suite.DB.Where("ssp_id = ? AND source_type = ?", fx.downstreamSSPID, string(risks.RiskSourceTypeInheritedRevoked)).First(&driftRisk).Error)
	suite.Equal(string(risks.RiskStatusOpen), driftRisk.Status)

	var responsibilityLink risks.RiskResponsibilityLink
	suite.Require().NoError(suite.DB.Where("risk_id = ? AND responsibility_uuid = ?", driftRisk.ID, fx.respID).First(&responsibilityLink).Error)

	suite.Require().Len(spy.calls, 1)
	suite.Equal(*driftRisk.ID, spy.calls[0].RiskID)
	suite.Equal(*reloadedLink.ID, spy.calls[0].LinkID)

	// Re-run the same re-publish (idempotency): no duplicate risk, no re-flip, no second
	// notification, since the link is already drifted and its Version hasn't moved again.
	spy.calls = nil
	resp = suite.publish(fx.upstreamSSPID, fx.offeringID, spy)
	suite.Equal(http.StatusOK, resp.Code)
	suite.Empty(spy.calls)
	var riskCount int64
	suite.Require().NoError(suite.DB.Model(&risks.Risk{}).Where("source_type = ?", string(risks.RiskSourceTypeInheritedRevoked)).Count(&riskCount).Error)
	suite.Equal(int64(1), riskCount)

	// Re-attest: clears drift and remediates the risk.
	leverageHandler := NewSSPLeverageHandler(zap.NewNop().Sugar(), suite.DB, &stubPDP{allow: true}, authz.FailClosed)
	attestCtx, attestRec := newReAttestRequestContext(fx.downstreamSSPID, *reloadedLink.ID)
	suite.Require().NoError(leverageHandler.ReAttest(attestCtx))
	suite.Equal(http.StatusOK, attestRec.Code)

	var attestedLink relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&attestedLink, "id = ?", link.ID).Error)
	suite.Equal(relational.SSPLeverageStatusActive, attestedLink.Status)
	suite.Equal(2, attestedLink.OfferingVersion)

	var remediatedRisk risks.Risk
	suite.Require().NoError(suite.DB.First(&remediatedRisk, "id = ?", driftRisk.ID).Error)
	suite.Equal(string(risks.RiskStatusRemediated), remediatedRisk.Status)

	// Isolation (AC #3): no risk was ever created for the upstream SSP, and the
	// downstream-facing projection response has no risk/evidence fields at all.
	var upstreamRiskCount int64
	suite.Require().NoError(suite.DB.Model(&risks.Risk{}).Where("ssp_id = ?", fx.upstreamSSPID).Count(&upstreamRiskCount).Error)
	suite.Zero(upstreamRiskCount)

	suite.assertProjectionExposesNoUpstreamRiskOrEvidence(fx.downstreamSSPID)
}

// TestDeprecateOfferingDriftsAndNotifies covers the offering-deprecated trigger,
// independent of any Version bump.
func (suite *LeverageDriftIntegrationSuite) TestDeprecateOfferingDriftsAndNotifies() {
	fx := seedDriftFixture(suite)
	link := suite.subscribe(fx)

	spy := &spyJobEnqueuer{}
	h := NewSSPExportOfferingHandler(zap.NewNop().Sugar(), suite.DB, spy)
	ctx, rec := newOfferingStatusRequestContext(fx.upstreamSSPID, fx.offeringID, `{"status":"deprecated"}`)
	suite.Require().NoError(h.UpdateOfferingStatus(ctx))
	suite.Equal(http.StatusOK, rec.Code)

	var reloadedLink relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&reloadedLink, "id = ?", link.ID).Error)
	suite.Equal(relational.SSPLeverageStatusDrifted, reloadedLink.Status)
	suite.Equal(1, reloadedLink.OfferingVersion, "deprecating must not touch OfferingVersion")

	suite.Require().Len(spy.calls, 1)
	suite.Equal("upstream offering deprecated", spy.calls[0].Reason)
}

// TestLeveragedAuthorizationDeleteDriftsAndNotifies covers the "leveraged authorization
// lapsed" trigger. Sharing no longer creates an LA, so this exercises a LEGACY link: one
// that references a hand-authored leveraged authorization (as pre-decoupling links did).
// Deleting that LA must still lapse the link.
func (suite *LeverageDriftIntegrationSuite) TestLeveragedAuthorizationDeleteDriftsAndNotifies() {
	fx := seedDriftFixture(suite)
	link := suite.subscribe(fx)

	// Attach a leveraged authorization to the link, simulating a legacy subscription.
	var downstreamSysImpl relational.SystemImplementation
	suite.Require().NoError(suite.DB.First(&downstreamSysImpl, "system_security_plan_id = ?", fx.downstreamSSPID).Error)
	auth := relational.LeveragedAuthorization{
		Title:                  "Legacy authorization",
		PartyUUID:              uuid.New(),
		SystemImplementationId: *downstreamSysImpl.ID,
	}
	suite.Require().NoError(suite.DB.Create(&auth).Error)
	suite.Require().NoError(suite.DB.Model(&relational.SSPLeverageLink{}).
		Where("id = ?", link.ID).Update("leveraged_auth_uuid", auth.ID).Error)

	spy := &spyJobEnqueuer{}
	sspHandler := NewSystemSecurityPlanHandler(zap.NewNop().Sugar(), suite.DB, nil, spy)
	ctx, rec := newDeleteLeveragedAuthRequestContext(fx.downstreamSSPID, *auth.ID)
	suite.Require().NoError(sspHandler.DeleteSystemImplementationLeveragedAuthorization(ctx))
	suite.Equal(http.StatusNoContent, rec.Code)

	var reloadedLink relational.SSPLeverageLink
	suite.Require().NoError(suite.DB.First(&reloadedLink, "id = ?", link.ID).Error)
	suite.Equal(relational.SSPLeverageStatusDrifted, reloadedLink.Status)

	suite.Require().Len(spy.calls, 1)
	suite.Equal("leveraged authorization revoked", spy.calls[0].Reason)
}

// assertProjectionExposesNoUpstreamRiskOrEvidence calls the existing (unchanged)
// LeveragedControls projection endpoint and confirms its JSON shape has no risk- or
// evidence-related keys at any level — AC #3's "never exposes the upstream's risk
// register" checked at the actual response shape, not just DB state.
func (suite *LeverageDriftIntegrationSuite) assertProjectionExposesNoUpstreamRiskOrEvidence(downstreamSSPID uuid.UUID) {
	h := NewSSPLeverageHandler(zap.NewNop().Sugar(), suite.DB, &stubPDP{allow: true}, authz.FailClosed)
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(downstreamSSPID.String())
	suite.Require().NoError(h.LeveragedControls(ctx))
	suite.Equal(http.StatusOK, rec.Code)

	raw := rec.Body.String()
	suite.NotContains(raw, `"risk`)
	suite.NotContains(raw, `"evidence`)

	var parsed map[string]any
	suite.Require().NoError(json.Unmarshal([]byte(raw), &parsed))
}
