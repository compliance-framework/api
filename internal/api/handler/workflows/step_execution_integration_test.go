//go:build integration

package workflows

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
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
	handler := NewStepExecutionHandler(logger, db)
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

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemName:           "test-system",
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

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemName:           "test-system",
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

func TestStepExecutionHandler_UpdateStatus(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemName:           "test-system",
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
		reqBody := UpdateStepStatusRequest{
			Status: "completed",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/step-executions/"+stepExec.ID.String()+"/status", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err = handler.UpdateStatus(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response StepExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "completed", response.Data.Status)
	})
}

func TestStepExecutionHandler_SubmitEvidence(t *testing.T) {
	handler, db := setupStepExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemName:           "test-system",
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

	evidenceID := uuid.New()

	t.Run("Success", func(t *testing.T) {
		reqBody := SubmitEvidenceRequest{
			EvidenceID: &evidenceID,
			Notes:      "Test evidence submission",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/step-executions/"+stepExec.ID.String()+"/evidence", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepExec.ID.String())

		err = handler.SubmitEvidence(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
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

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Instance",
		SystemName:           "test-system",
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
