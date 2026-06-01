//go:build integration

package oscal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	workflowevidence "github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

func (suite *ProfileIntegrationSuite) TestComplianceProgressIncludesWorkflowCompletionEvidence() {
	suite.Require().NoError(suite.DB.AutoMigrate(
		&workflows.WorkflowDefinition{},
		&workflows.WorkflowInstance{},
		&workflows.RoleAssignment{},
		&workflows.WorkflowExecution{},
		&workflows.WorkflowStepDefinition{},
		&workflows.StepExecution{},
		&workflows.ControlRelationship{},
	))

	catalogID := uuid.New()
	control := relational.Control{CatalogID: catalogID, ID: "ctrl-workflow", Title: "Workflow Control"}
	suite.Require().NoError(suite.DB.Create(&control).Error)

	profileID := uuid.New()
	profile := relational.Profile{
		UUIDModel: relational.UUIDModel{ID: &profileID},
		Metadata:  relational.Metadata{Title: "Workflow Profile"},
	}
	suite.Require().NoError(suite.DB.Create(&profile).Error)
	suite.Require().NoError(suite.DB.Model(&profile).Association("Controls").Append(&control))

	definition := workflows.WorkflowDefinition{
		Name:             "Workflow Review",
		Version:          "1.0",
		SuggestedCadence: string(workflows.CadenceWeekly),
	}
	suite.Require().NoError(suite.DB.Create(&definition).Error)

	relationship := workflows.ControlRelationship{
		WorkflowDefinitionID: definition.ID,
		ControlID:            control.ID,
		ControlSource:        "Test Catalog",
		CatalogID:            catalogID.String(),
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	suite.Require().NoError(suite.DB.Create(&relationship).Error)
	suite.Require().NoError(workflows.NewFilterSyncService(suite.DB, zap.NewNop().Sugar()).SyncFilterForDefinition(*definition.ID))

	sspID := uuid.New()
	instance := workflows.WorkflowInstance{
		WorkflowDefinitionID: definition.ID,
		Name:                 "Workflow Instance",
		Cadence:              string(workflows.CadenceWeekly),
		SystemSecurityPlanID: &sspID,
	}
	suite.Require().NoError(suite.DB.Create(&instance).Error)

	startedAt := time.Now().Add(-time.Hour)
	completedAt := time.Now()
	execution := workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             workflows.WorkflowStatusCompleted.String(),
		TriggeredBy:        "manual",
		StartedAt:          &startedAt,
		CompletedAt:        &completedAt,
	}
	suite.Require().NoError(suite.DB.Create(&execution).Error)
	suite.Require().NoError(workflowevidence.NewEvidenceIntegration(suite.DB, zap.NewNop().Sugar()).AddExecutionCompletionEvidence(context.Background(), execution.ID))

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/profiles/"+profileID.String()+"/compliance-progress", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(profileID.String())

	suite.Require().NoError(NewProfileHandler(zap.NewNop().Sugar(), suite.DB).ComplianceProgress(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code)

	var response struct {
		Data ProfileComplianceProgress `json:"data"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Require().Equal(1, response.Data.Summary.TotalControls)
	suite.Require().Equal(1, response.Data.Summary.Satisfied)
	suite.Require().Len(response.Data.Controls, 1)
	suite.Require().Equal("satisfied", response.Data.Controls[0].ComputedStatus)

	laterStartedAt := completedAt.Add(time.Hour)
	nextExecution := workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             workflows.WorkflowStatusPending.String(),
		TriggeredBy:        "manual",
		StartedAt:          &laterStartedAt,
	}
	suite.Require().NoError(suite.DB.Create(&nextExecution).Error)
	suite.Require().NoError(workflowevidence.NewEvidenceIntegration(suite.DB, zap.NewNop().Sugar()).AddWorkflowExecutionEvidence(context.Background(), nextExecution.ID, "started"))

	req = httptest.NewRequest(http.MethodGet, "/profiles/"+profileID.String()+"/compliance-progress", nil)
	rec = httptest.NewRecorder()
	ctx = e.NewContext(req, rec)
	ctx.SetParamNames("id")
	ctx.SetParamValues(profileID.String())

	suite.Require().NoError(NewProfileHandler(zap.NewNop().Sugar(), suite.DB).ComplianceProgress(ctx))
	suite.Require().Equal(http.StatusOK, rec.Code)

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Require().Equal(1, response.Data.Summary.TotalControls)
	suite.Require().Equal(1, response.Data.Summary.Satisfied)
	suite.Require().Len(response.Data.Controls, 1)
	suite.Require().Equal("satisfied", response.Data.Controls[0].ComputedStatus)
}
