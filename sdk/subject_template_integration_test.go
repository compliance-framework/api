//go:build integration

package sdk_test

import (
	"context"
	"testing"

	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
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

func (suite *SubjectTemplateSDKIntegrationSuite) TestUpsertSendsDisplayPriorityAndComponentTypeAndLogsWarnings() {
	suite.Require().NoError(suite.Migrator.Refresh())

	core, logs := observer.New(zapcore.WarnLevel)
	client, err := suite.GetAuthenticatedSDKTestClientWithLogger(zap.New(core).Sugar())
	suite.Require().NoError(err)

	componentID := uuid.NewString()
	resourceID := uuid.NewString()
	selector := []types.SubjectTemplateSelectorLabel{{Key: "_plugin", Value: "plugin-b"}}
	err = client.SubjectTemplate.Upsert(context.Background(), "plugin-b",
		types.SubjectTemplate{
			ID:                componentID,
			Name:              "Repository",
			Type:              "component",
			IdentityLabelKeys: []string{"repository"},
			SourceMode:        "runtime-derived",
			DisplayPriority:   10,
			ComponentType:     "software",
			SelectorLabels:    selector,
			LabelSchema:       []types.SubjectTemplateLabelSchema{{Key: "repository"}},
		},
		types.SubjectTemplate{
			ID:                resourceID,
			Name:              "Cloud resource",
			Type:              "resource",
			IdentityLabelKeys: []string{"resource_id"},
			SourceMode:        "runtime-derived",
			SelectorLabels:    selector,
			LabelSchema:       []types.SubjectTemplateLabelSchema{{Key: "resource_id"}},
		},
	)
	suite.Require().NoError(err)

	var stored templaterel.SubjectTemplate
	suite.Require().NoError(suite.DB.First(&stored, "id = ?", componentID).Error)
	suite.Equal(10, stored.DisplayPriority)
	suite.Require().NotNil(stored.ComponentType)
	suite.Equal("software", *stored.ComponentType)

	warnings := logs.FilterMessage("Subject template warning").All()
	suite.Require().Len(warnings, 1, "the non-component template is reported")
	suite.Contains(warnings[0].ContextMap()["warning"], resourceID)
}
