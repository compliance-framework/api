//go:build integration

package worker

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

// RiskEvidenceWorkerResponsibilityIntegrationSuite exercises resolveSSPsViaFilters's
// BCH-1339 second arm (filter_responsibilities → ssp_leverage_links) against real
// Postgres, complementing the sqlite unit tests in risk_evidence_worker_test.go — in
// particular the uuid column types and casing that only a real Postgres schema exercises.
type RiskEvidenceWorkerResponsibilityIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestRiskEvidenceWorkerResponsibilityIntegrationSuite(t *testing.T) {
	suite.Run(t, new(RiskEvidenceWorkerResponsibilityIntegrationSuite))
}

func (suite *RiskEvidenceWorkerResponsibilityIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

// seedLeveragedResponsibility creates the minimal real-schema graph a
// filter_responsibilities → ssp_leverage_links resolution needs: an Export with one
// ProvidedControlImplementation and one ControlImplementationResponsibility under it, a
// downstream SystemSecurityPlan, and an SSPLeverageLink tying the two together. Returns
// the responsibility uuid and the downstream SSP id.
func (suite *RiskEvidenceWorkerResponsibilityIntegrationSuite) seedLeveragedResponsibility() (responsibilityUUID uuid.UUID, downstreamSSPID uuid.UUID) {
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

	return *responsibility.ID, *downstreamSSP.ID
}

func (suite *RiskEvidenceWorkerResponsibilityIntegrationSuite) seedResponsibilityFilter(downstreamSSPID, responsibilityUUID uuid.UUID, labelKey, labelValue string) {
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

func (suite *RiskEvidenceWorkerResponsibilityIntegrationSuite) TestResolvesDownstreamSSPViaFilterResponsibilities() {
	responsibilityUUID, downstreamSSPID := suite.seedLeveragedResponsibility()
	suite.seedResponsibilityFilter(downstreamSSPID, responsibilityUUID, "environment", "production")

	worker := NewRiskEvidenceWorker(suite.DB, zap.NewNop().Sugar())
	sspInfos, responsibilityInfos, err := worker.resolveSSPsViaFilters(context.Background(), []relational.Labels{
		{Name: "environment", Value: "production"},
	})
	suite.Require().NoError(err)
	suite.Empty(sspInfos)
	suite.Require().Len(responsibilityInfos, 1)
	suite.Equal(downstreamSSPID, responsibilityInfos[0].SSPID)
	suite.Equal(responsibilityUUID, responsibilityInfos[0].ResponsibilityUUID)
}

func (suite *RiskEvidenceWorkerResponsibilityIntegrationSuite) TestNoMatchReturnsNoSSPs() {
	responsibilityUUID, downstreamSSPID := suite.seedLeveragedResponsibility()
	suite.seedResponsibilityFilter(downstreamSSPID, responsibilityUUID, "environment", "staging")

	worker := NewRiskEvidenceWorker(suite.DB, zap.NewNop().Sugar())
	sspInfos, responsibilityInfos, err := worker.resolveSSPsViaFilters(context.Background(), []relational.Labels{
		{Name: "environment", Value: "production"},
	})
	suite.Require().NoError(err)
	suite.Empty(sspInfos)
	suite.Empty(responsibilityInfos)
}
