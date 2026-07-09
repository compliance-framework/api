//go:build integration

package worker

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	poamsvc "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// InheritedResponsibilityRiskIntegrationSuite exercises BCH-1340's full worker pipeline
// (Work(), not just resolveSSPsViaFilters) against real Postgres: a leveraged
// responsibility + matching risk template + non-compliant evidence creates exactly one
// inherited-responsibility risk on the downstream SSP, deduped on re-processing, and
// auto-remediated once the evidence flips to satisfied. Also covers the isolation
// requirement (a control-arm-only match stays on the upstream SSP) and the
// promote-to-POA&M regression (works unchanged for this new source type).
type InheritedResponsibilityRiskIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestInheritedResponsibilityRiskIntegrationSuite(t *testing.T) {
	suite.Run(t, new(InheritedResponsibilityRiskIntegrationSuite))
}

func (suite *InheritedResponsibilityRiskIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

func (suite *InheritedResponsibilityRiskIntegrationSuite) newWorker() *RiskEvidenceWorker {
	return NewRiskEvidenceWorker(suite.DB, zap.NewNop().Sugar())
}

// seedLeveragedResponsibility creates the minimal real-schema graph a
// filter_responsibilities → ssp_leverage_links resolution needs (mirroring
// RiskEvidenceWorkerResponsibilityIntegrationSuite's BCH-1339 helper): an Export with one
// ProvidedControlImplementation and one ControlImplementationResponsibility under it, an
// upstream and downstream SystemSecurityPlan, and an SSPLeverageLink tying the two
// together.
func (suite *InheritedResponsibilityRiskIntegrationSuite) seedLeveragedResponsibility() (responsibilityUUID, downstreamSSPID, upstreamSSPID uuid.UUID) {
	export := relational.Export{}
	suite.Require().NoError(suite.DB.Create(&export).Error)

	provided := relational.ProvidedControlImplementation{ExportId: *export.ID, Description: "provided"}
	suite.Require().NoError(suite.DB.Create(&provided).Error)

	responsibility := relational.ControlImplementationResponsibility{
		ExportId: *export.ID, ProvidedUuid: *provided.ID, Description: "responsibility",
	}
	suite.Require().NoError(suite.DB.Create(&responsibility).Error)

	upstreamSSP := relational.SystemSecurityPlan{}
	suite.Require().NoError(suite.DB.Create(&upstreamSSP).Error)

	downstreamSSP := relational.SystemSecurityPlan{}
	suite.Require().NoError(suite.DB.Create(&downstreamSSP).Error)

	link := relational.SSPLeverageLink{
		DownstreamSSPID:   *downstreamSSP.ID,
		UpstreamSSPID:     *upstreamSSP.ID,
		OfferingID:        uuid.New(),
		ControlID:         "ac-1",
		ProvidedUUID:      *provided.ID,
		InheritedUUID:     uuid.New(),
		LeveragedAuthUUID: uuid.New(),
		Satisfaction:      relational.SSPLeverageSatisfactionPartial,
		Status:            relational.SSPLeverageStatusActive,
	}
	suite.Require().NoError(suite.DB.Create(&link).Error)

	return *responsibility.ID, *downstreamSSP.ID, *upstreamSSP.ID
}

func (suite *InheritedResponsibilityRiskIntegrationSuite) seedResponsibilityFilter(downstreamSSPID, responsibilityUUID uuid.UUID, labelKey, labelValue string) {
	filterScope := labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Condition: &labelfilter.Condition{Label: labelKey, Operator: "=", Value: labelValue},
		},
	}
	f := relational.Filter{Name: "responsibility-filter", Filter: datatypes.NewJSONType(filterScope)}
	suite.Require().NoError(suite.DB.Create(&f).Error)
	suite.Require().NoError(suite.DB.Create(&relational.FilterResponsibility{
		FilterID:           *f.ID,
		ResponsibilityUUID: responsibilityUUID,
		SSPID:              downstreamSSPID,
	}).Error)
}

func (suite *InheritedResponsibilityRiskIntegrationSuite) TestCreatedDedupedAndRemediated() {
	responsibilityUUID, downstreamSSPID, upstreamSSPID := suite.seedLeveragedResponsibility()
	suite.seedResponsibilityFilter(downstreamSSPID, responsibilityUUID, "environment", "production")

	riskTemplate := createTestRiskTemplate(suite.T(), suite.DB)
	evidence := createTestEvidence(suite.T(), suite.DB)

	worker := suite.newWorker()
	ctx := context.Background()
	args := RiskProcessEvidenceArgs{EvidenceID: *evidence.ID, EvidenceEnd: "2026-01-01T00:00:00Z", Status: "not-satisfied"}
	suite.Require().NoError(worker.Work(ctx, &river.Job[RiskProcessEvidenceArgs]{Args: args}))

	var risk risks.Risk
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", downstreamSSPID).First(&risk).Error)
	suite.Equal(string(risks.RiskSourceTypeInheritedResponsibility), risk.SourceType)
	suite.Equal(string(risks.RiskStatusOpen), risk.Status)
	suite.Require().NotNil(risk.RiskTemplateID)
	suite.Equal(*riskTemplate.ID, *risk.RiskTemplateID)

	var responsibilityLink risks.RiskResponsibilityLink
	suite.Require().NoError(suite.DB.Where("risk_id = ? AND responsibility_uuid = ?", risk.ID, responsibilityUUID).First(&responsibilityLink).Error)

	var upstreamRiskCount int64
	suite.Require().NoError(suite.DB.Model(&risks.Risk{}).Where("ssp_id = ?", upstreamSSPID).Count(&upstreamRiskCount).Error)
	suite.Zero(upstreamRiskCount, "no risk should ever land on the upstream SSP for a responsibility-only match")

	// Re-run the same evidence job — dedupe by responsibility uuid must not duplicate.
	suite.Require().NoError(worker.Work(ctx, &river.Job[RiskProcessEvidenceArgs]{Args: args}))
	var riskCount int64
	suite.Require().NoError(suite.DB.Model(&risks.Risk{}).Where("ssp_id = ?", downstreamSSPID).Count(&riskCount).Error)
	suite.Equal(int64(1), riskCount)

	// Flip: newer evidence for the same stream, now satisfied, auto-remediates the risk —
	// exercising the existing (unmodified) handleEvidenceResolution path end to end.
	satisfiedID := uuid.New()
	satisfied := &relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &satisfiedID},
		UUID:      evidence.UUID,
		Title:     "Satisfied Evidence",
		Start:     evidence.Start,
		End:       evidence.End.Add(1),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
	}
	suite.Require().NoError(suite.DB.Create(satisfied).Error)

	satisfiedArgs := RiskProcessEvidenceArgs{EvidenceID: satisfiedID, EvidenceEnd: "2026-01-02T00:00:00Z", Status: "satisfied"}
	suite.Require().NoError(worker.Work(ctx, &river.Job[RiskProcessEvidenceArgs]{Args: satisfiedArgs}))

	var remediated risks.Risk
	suite.Require().NoError(suite.DB.First(&remediated, "id = ?", risk.ID).Error)
	suite.Equal(string(risks.RiskStatusRemediated), remediated.Status)
}

func (suite *InheritedResponsibilityRiskIntegrationSuite) TestIsolationUpstreamOnlyMatchStaysUpstream() {
	catalogID := uuid.New()
	controlID := "AC-1"
	seedFilterForControl(suite.T(), suite.DB, catalogID, controlID, "environment", "production")
	upstreamSSP := createTestSSPWithControl(suite.T(), suite.DB, catalogID, controlID)

	createTestRiskTemplate(suite.T(), suite.DB)
	evidence := createTestEvidence(suite.T(), suite.DB)

	worker := suite.newWorker()
	ctx := context.Background()
	args := RiskProcessEvidenceArgs{EvidenceID: *evidence.ID, EvidenceEnd: "2026-01-01T00:00:00Z", Status: "not-satisfied"}
	suite.Require().NoError(worker.Work(ctx, &river.Job[RiskProcessEvidenceArgs]{Args: args}))

	var risk risks.Risk
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", *upstreamSSP.ID).First(&risk).Error)
	suite.Equal(string(risks.RiskSourceTypeEvidenceAuto), risk.SourceType)

	var inheritedResponsibilityCount int64
	suite.Require().NoError(suite.DB.Model(&risks.Risk{}).
		Where("source_type = ?", string(risks.RiskSourceTypeInheritedResponsibility)).
		Count(&inheritedResponsibilityCount).Error)
	suite.Zero(inheritedResponsibilityCount, "a filter_controls-only match must never create an inherited-responsibility risk")

	var responsibilityLinkCount int64
	suite.Require().NoError(suite.DB.Model(&risks.RiskResponsibilityLink{}).Count(&responsibilityLinkCount).Error)
	suite.Zero(responsibilityLinkCount)
}

func (suite *InheritedResponsibilityRiskIntegrationSuite) TestPromotesToPoamUnchanged() {
	responsibilityUUID, downstreamSSPID, _ := suite.seedLeveragedResponsibility()
	suite.seedResponsibilityFilter(downstreamSSPID, responsibilityUUID, "environment", "production")

	createTestRiskTemplate(suite.T(), suite.DB)
	evidence := createTestEvidence(suite.T(), suite.DB)

	worker := suite.newWorker()
	ctx := context.Background()
	args := RiskProcessEvidenceArgs{EvidenceID: *evidence.ID, EvidenceEnd: "2026-01-01T00:00:00Z", Status: "not-satisfied"}
	suite.Require().NoError(worker.Work(ctx, &river.Job[RiskProcessEvidenceArgs]{Args: args}))

	var risk risks.Risk
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", downstreamSSPID).First(&risk).Error)
	suite.Require().Equal(string(risks.RiskSourceTypeInheritedResponsibility), risk.SourceType)

	// PromoteToPoam requires "investigating" status — a pre-existing, source-type-agnostic
	// triage step that's out of this ticket's scope; simulate it directly.
	suite.Require().NoError(suite.DB.Model(&risk).Update("status", string(risks.RiskStatusInvestigating)).Error)

	poamItem, err := risks.NewRiskService(suite.DB).PromoteToPoam(poamsvc.NewPoamService(suite.DB), risks.PromoteToPoamParams{
		RiskID: *risk.ID,
	})
	suite.Require().NoError(err)
	suite.Require().NotNil(poamItem)

	var promoted risks.Risk
	suite.Require().NoError(suite.DB.First(&promoted, "id = ?", risk.ID).Error)
	suite.Equal(string(risks.RiskStatusMitigatingPlanned), promoted.Status)
}
