//go:build integration

package sdk_test

import (
	"context"
	"testing"

	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

func TestRiskTemplateSDK(t *testing.T) {
	suite.Run(t, new(RiskTemplateSDKIntegrationSuite))
}

type RiskTemplateSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *RiskTemplateSDKIntegrationSuite) TestUpsertWithAgentAuth() {
	suite.Require().NoError(suite.Migrator.Refresh())

	client, err := suite.GetAuthenticatedSDKTestClient()
	suite.Require().NoError(err)

	templateID := uuid.NewString()
	err = client.RiskTemplate.Upsert(context.Background(), "plugin-a", "package-a", types.RiskTemplate{
		ID:           templateID,
		Name:         "Template A",
		Title:        "Template A",
		Statement:    "Template statement",
		ViolationIds: []string{"violation-a"},
	})
	suite.Require().NoError(err)

	var count int64
	suite.Require().NoError(suite.DB.Model(&templaterel.RiskTemplate{}).Where("id = ?", templateID).Count(&count).Error)
	suite.Equal(int64(1), count)
}
