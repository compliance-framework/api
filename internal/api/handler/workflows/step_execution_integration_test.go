//go:build integration

package workflows

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func setupStepExecutionTestHandler(t *testing.T) (*StepExecutionHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()

	// Create evidence integration first
	evidenceIntegration := workflow.NewEvidenceIntegration(db, logger)

	// Create services needed for step transition
	stepExecService := workflows.NewStepExecutionService(db, evidenceIntegration)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	workflowInstanceService := workflows.NewWorkflowInstanceService(db)
	workflowDefinitionService := workflows.NewWorkflowDefinitionService(db)
	roleAssignmentService := workflows.NewRoleAssignmentService(db)

	// Set the workflow execution service on evidence integration to use the same instance
	evidenceIntegration.SetWorkflowExecutionService(workflowExecService)

	// Create executor for step transition coordination
	stdLogger := log.Default()
	executor := workflow.NewDAGExecutor(
		stepExecService,
		workflowExecService,
		stepDefService,
		stdLogger,
	)

	// Create step transition service
	transitionService := workflow.NewStepTransitionService(
		stepExecService,
		stepDefService,
		workflowExecService,
		roleAssignmentService,
		workflowInstanceService,
		workflowDefinitionService,
		executor,
		db,
		evidenceIntegration,
	)

	handler := NewStepExecutionHandler(logger, db, transitionService)
	return handler, db
}

func TestStepExecutionHandler_List(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "in_progress",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions?workflow_execution_id="+execution.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 1)
	})

	t.Run("MissingWorkflowExecutionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestStepExecutionHandler_Get(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)
	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "in_progress",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/"+stepExec.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, stepExec.ID.String(), response.Data.ID.String())
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestStepExecutionHandler_TransitionStep(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
		EvidenceRequired:     []workflows.EvidenceRequirement{},
	}
	require.NoError(t, db.Create(stepDef).Error)

	// Create role assignment for the user
	roleAssignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "test-user",
		IsActive:           true,
	}
	require.NoError(t, db.Create(roleAssignment).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		// First transition from pending to in_progress
		reqBody := TransitionStepRequest{
			Status:   "in_progress",
			UserID:   "test-user",
			UserType: "user",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/transition", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err = handler.TransitionStep(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Then transition from in_progress to completed
		reqBody = TransitionStepRequest{
			Status:   "completed",
			UserID:   "test-user",
			UserType: "user",
		}

		body, err = json.Marshal(reqBody)
		require.NoError(t, err)

		req = httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/transition", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec = httptest.NewRecorder()
		c = e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err = handler.TransitionStep(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		require.NotNil(t, response)
		require.NotNil(t, response.Data)
		assert.Equal(t, "completed", response.Data.Status)
	})
}

func TestStepExecutionHandler_GetEvidenceRequirements(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)
	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
		EvidenceRequired: []workflows.EvidenceRequirement{
			{
				Type:     "Documentation",
				Required: true,
			},
		},
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/step-executions/"+stepExec.ID.String()+"/evidence-requirements", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err := handler.GetEvidenceRequirements(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response map[string]interface{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response["data"])
	})
}

func TestStepExecutionHandler_Fail(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	sysId := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemSecurityPlanID: &sysId,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "in_progress",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		reqBody := FailStepRequest{
			Reason: "Test failed due to validation error",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/fail", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err = handler.Fail(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "failed", response.Data.Status)
	})
}
