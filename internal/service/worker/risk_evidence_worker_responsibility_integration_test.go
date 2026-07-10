//go:build integration

package worker

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
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

func (suite *RiskEvidenceWorkerResponsibilityIntegrationSuite) TestResolvesDownstreamSSPViaFilterResponsibilities() {
	responsibilityUUID, downstreamSSPID, _ := seedLeveragedResponsibility(suite.T(), suite.DB)
	seedResponsibilityFilter(suite.T(), suite.DB, downstreamSSPID, responsibilityUUID, "environment", "production")

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
	responsibilityUUID, downstreamSSPID, _ := seedLeveragedResponsibility(suite.T(), suite.DB)
	seedResponsibilityFilter(suite.T(), suite.DB, downstreamSSPID, responsibilityUUID, "environment", "staging")

	worker := NewRiskEvidenceWorker(suite.DB, zap.NewNop().Sugar())
	sspInfos, responsibilityInfos, err := worker.resolveSSPsViaFilters(context.Background(), []relational.Labels{
		{Name: "environment", Value: "production"},
	})
	suite.Require().NoError(err)
	suite.Empty(sspInfos)
	suite.Empty(responsibilityInfos)
}
