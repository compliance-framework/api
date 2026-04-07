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

func TestSubjectTemplateSDK(t *testing.T) {
	suite.Run(t, new(SubjectTemplateSDKIntegrationSuite))
}

type SubjectTemplateSDKIntegrationSuite struct {
	IntegrationBaseTestSuite
}

func (suite *SubjectTemplateSDKIntegrationSuite) TestUpsertWithAgentAuth() {
	suite.Require().NoError(suite.Migrator.Refresh())

	client, err := suite.GetAuthenticatedSDKTestClient()
	suite.Require().NoError(err)

	templateID := uuid.NewString()
	err = client.SubjectTemplate.Upsert(context.Background(), "plugin-a", types.SubjectTemplate{
		ID:                templateID,
		Name:              "Template A",
		Type:              "component",
		IdentityLabelKeys: []string{"asset_id"},
		SourceMode:        "runtime-derived",
		SelectorLabels: []types.SubjectTemplateSelectorLabel{
			{Key: "_plugin", Value: "plugin-a"},
		},
		LabelSchema: []types.SubjectTemplateLabelSchema{
			{Key: "asset_id"},
		},
	})
	suite.Require().NoError(err)

	var count int64
	suite.Require().NoError(suite.DB.Model(&templaterel.SubjectTemplate{}).Where("id = ?", templateID).Count(&count).Error)
	suite.Equal(int64(1), count)
}
