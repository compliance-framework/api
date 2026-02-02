//go:build integration

package workflows

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// MockRiverClient mocks the River client for testing
type MockRiverClient struct {
	mock.Mock
}

func (m *MockRiverClient) InsertMany(ctx context.Context, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*rivertype.JobInsertResult), args.Error(1)
}

func setupExecutionTestHandler(t *testing.T) (*WorkflowExecutionHandler, *gorm.DB, *workflow.Manager) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()

	// Create services for the manager
	stepExecService := workflows.NewStepExecutionService(db, nil)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	workflowInstService := workflows.NewWorkflowInstanceService(db)

	// Create a mock river client for testing
	mockRiver := &MockRiverClient{}
	mockRiver.On("InsertMany", mock.Anything, mock.Anything).Return([]*rivertype.JobInsertResult{}, nil)

	// For testing, we'll use a manager with mock river client
	manager := workflow.NewManager(
		mockRiver,
		workflowExecService,
		workflowInstService,
		stepExecService,
		logger,
	)

	handler := NewWorkflowExecutionHandler(logger, db, manager)
	return handler, db, manager
}

func TestWorkflowExecutionHandler_Start(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	// Create test data
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

	t.Run("Success", func(t *testing.T) {
		reqBody := StartWorkflowExecutionRequest{
			WorkflowInstanceID: instance.ID,
			TriggeredBy:        "manual",
			TriggeredByID:      "user-123",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/executions", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Start(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response WorkflowExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.NotNil(t, response.Data.ID)
		assert.Equal(t, "manual", response.Data.TriggeredBy)
		assert.Equal(t, "user-123", response.Data.TriggeredByID)
	})

	t.Run("ValidationError_MissingWorkflowInstanceID", func(t *testing.T) {
		reqBody := StartWorkflowExecutionRequest{
			TriggeredBy: "manual",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/executions", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Start(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowExecutionHandler_List(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
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

	exec1 := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "completed",
		TriggeredBy:        "manual",
	}
	exec2 := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "scheduled",
	}

	require.NoError(t, db.Create(exec1).Error)
	require.NoError(t, db.Create(exec2).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/executions?workflow_instance_id="+instance.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowExecutionListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("MissingWorkflowInstanceID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/executions", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowExecutionHandler_Get(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
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
		Status:             "completed",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/executions/"+execution.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(execution.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, execution.ID.String(), response.Data.ID.String())
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/executions/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestWorkflowExecutionHandler_GetStatus(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
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

	// Create some step executions
	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "completed",
	}
	require.NoError(t, db.Create(stepExec).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/executions/"+execution.ID.String()+"/status", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(execution.ID.String())

		err := handler.GetStatus(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowExecutionStatusResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, "in_progress", response.Data.Status)
		assert.Equal(t, 1, response.Data.TotalSteps)
		assert.Equal(t, 1, response.Data.CompletedSteps)
	})
}

func TestWorkflowExecutionHandler_GetMetrics(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
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
		Status:             "completed",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/executions/"+execution.ID.String()+"/metrics", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(execution.ID.String())

		err := handler.GetMetrics(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowExecutionMetricsResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, *execution.ID, response.Data.ExecutionID)
	})
}

func TestWorkflowExecutionHandler_Cancel(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
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

	t.Run("Success", func(t *testing.T) {
		reqBody := CancelWorkflowExecutionRequest{
			Reason: "User requested cancellation",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/executions/"+execution.ID.String()+"/cancel", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(execution.ID.String())

		err = handler.Cancel(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "cancelled", response.Data.Status)
	})
}

func TestWorkflowExecutionHandler_Retry(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
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
		Status:             "failed",
		TriggeredBy:        "manual",
		FailureReason:      "Something went wrong",
	}
	require.NoError(t, db.Create(execution).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/workflows/executions/"+execution.ID.String()+"/retry", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(execution.ID.String())

		err := handler.Retry(c)
		require.NoError(t, err)

		// Check if we got an error response
		if rec.Code != http.StatusCreated {
			t.Logf("Retry failed with status %d: %s", rec.Code, rec.Body.String())
		}
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response WorkflowExecutionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		if response.Data != nil {
			assert.NotEqual(t, execution.ID, response.Data.ID) // Should be a new execution
			assert.Equal(t, "pending", response.Data.Status)
		}
	})
}
