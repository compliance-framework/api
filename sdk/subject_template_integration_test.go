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
	_, err = client.SubjectTemplate.Upsert(context.Background(), "plugin-a", types.SubjectTemplate{
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

func (suite *SubjectTemplateSDKIntegrationSuite) TestUpsertRoundTripsNewFieldsAndReturnsWarnings() {
	suite.Require().NoError(suite.Migrator.Refresh())

	client, err := suite.GetAuthenticatedSDKTestClient()
	suite.Require().NoError(err)

	componentID := uuid.NewString()
	resourceID := uuid.NewString()
	result, err := client.SubjectTemplate.Upsert(context.Background(), "plugin-a",
		types.SubjectTemplate{
			ID:                componentID,
			Name:              "Component A",
			Type:              "component",
			IdentityLabelKeys: []string{"asset_id"},
			SourceMode:        "runtime-derived",
			DisplayPriority:   7,
			ComponentType:     stringPtr("software"),
			SelectorLabels: []types.SubjectTemplateSelectorLabel{
				{Key: "_plugin", Value: "plugin-a"},
			},
			LabelSchema: []types.SubjectTemplateLabelSchema{
				{Key: "asset_id"},
			},
		},
		types.SubjectTemplate{
			ID:                resourceID,
			Name:              "Bucket",
			Type:              "resource",
			IdentityLabelKeys: []string{"asset_id"},
			SourceMode:        "runtime-derived",
			SelectorLabels: []types.SubjectTemplateSelectorLabel{
				{Key: "_plugin", Value: "plugin-a"},
			},
			LabelSchema: []types.SubjectTemplateLabelSchema{
				{Key: "asset_id"},
			},
		},
	)
	suite.Require().NoError(err)
	suite.Require().NotNil(result)
	suite.Equal([]string{"template Bucket has type resource and will not produce subjects"}, result.Warnings)

	var stored templaterel.SubjectTemplate
	suite.Require().NoError(suite.DB.First(&stored, "id = ?", componentID).Error)
	suite.Equal(7, stored.DisplayPriority)
	suite.Require().NotNil(stored.ComponentType)
	suite.Equal("software", *stored.ComponentType)
}

func stringPtr(value string) *string {
	return &value
}
