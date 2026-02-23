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
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/service/relational"
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
	roleAssignmentService := workflows.NewRoleAssignmentService(db)
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, zap.NewNop().Sugar(), nil)

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
		nil,
	)

	handler := NewWorkflowExecutionHandler(logger, db, manager, assignmentService)
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

func TestWorkflowExecutionHandler_ReassignRole(t *testing.T) {
	handler, db, _ := setupExecutionTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	actor := &relational.User{
		Email:      "bulk-actor@example.com",
		FirstName:  "Bulk",
		LastName:   "Actor",
		AuthMethod: "local",
		IsActive:   true,
	}
	require.NoError(t, db.Create(actor).Error)

	newAssignee := &relational.User{
		Email:      "bulk-new@example.com",
		FirstName:  "Bulk",
		LastName:   "Owner",
		AuthMethod: "local",
		IsActive:   true,
	}
	require.NoError(t, db.Create(newAssignee).Error)

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Bulk Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)
	sysID := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Bulk Instance",
		SystemSecurityPlanID: &sysID,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDefTarget := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Target Step",
		ResponsibleRole:      "it-ops",
	}
	require.NoError(t, db.Create(stepDefTarget).Error)
	stepDefTargetCompleted := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Target Step Completed",
		ResponsibleRole:      "it-ops",
	}
	require.NoError(t, db.Create(stepDefTargetCompleted).Error)

	stepDefOther := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Other Step",
		ResponsibleRole:      "reviewer",
	}
	require.NoError(t, db.Create(stepDefOther).Error)

	eligibleStep := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDefTarget.ID,
		Status:                   "pending",
		AssignedToType:           "group",
		AssignedToID:             "old-group",
	}
	require.NoError(t, db.Create(eligibleStep).Error)

	ineligibleStep := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDefTargetCompleted.ID,
		Status:                   "completed",
		AssignedToType:           "group",
		AssignedToID:             "old-completed",
	}
	require.NoError(t, db.Create(ineligibleStep).Error)

	otherRoleStep := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDefOther.ID,
		Status:                   "pending",
		AssignedToType:           "group",
		AssignedToID:             "other-role",
	}
	require.NoError(t, db.Create(otherRoleStep).Error)

	createContext := func(req *http.Request, rec *httptest.ResponseRecorder, executionID string) echo.Context {
		c := e.NewContext(req, rec)
		c.Set("user", &authn.UserClaims{
			GivenName:  actor.FirstName,
			FamilyName: actor.LastName,
		})
		claims := c.Get("user").(*authn.UserClaims)
		claims.Subject = actor.Email
		c.SetParamNames("id")
		c.SetParamValues(executionID)
		return c
	}

	t.Run("Success", func(t *testing.T) {
		reqBody := ReassignRoleRequest{
			RoleName:          "it-ops",
			NewAssignedToType: "user",
			NewAssignedToID:   newAssignee.ID.String(),
			Reason:            "team rotation",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/executions/"+execution.ID.String()+"/reassign-role", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := createContext(req, rec, execution.ID.String())

		err = handler.ReassignRole(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response BulkReassignRoleResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
		assert.Equal(t, *execution.ID, response.Data.ExecutionID)
		assert.Equal(t, "it-ops", response.Data.RoleName)
		assert.Equal(t, 1, response.Data.ReassignedCount)
		require.Len(t, response.Data.ReassignedStepExecutionIDs, 1)
		assert.Equal(t, *eligibleStep.ID, response.Data.ReassignedStepExecutionIDs[0])

		var updated workflows.StepExecution
		require.NoError(t, db.First(&updated, eligibleStep.ID).Error)
		assert.Equal(t, "user", updated.AssignedToType)
		assert.Equal(t, newAssignee.ID.String(), updated.AssignedToID)

		var unchangedCompleted workflows.StepExecution
		require.NoError(t, db.First(&unchangedCompleted, ineligibleStep.ID).Error)
		assert.Equal(t, "old-completed", unchangedCompleted.AssignedToID)

		var unchangedOtherRole workflows.StepExecution
		require.NoError(t, db.First(&unchangedOtherRole, otherRoleStep.ID).Error)
		assert.Equal(t, "other-role", unchangedOtherRole.AssignedToID)

		var history []workflows.StepReassignmentHistory
		require.NoError(t, db.Where("step_execution_id = ?", eligibleStep.ID).Find(&history).Error)
		require.Len(t, history, 1)
		assert.Equal(t, actor.Email, history[0].ReassignedByEmail)
	})

	t.Run("Error_InvalidAssignee", func(t *testing.T) {
		reqBody := map[string]string{
			"role-name":            "it-ops",
			"new-assigned-to-type": "invalid",
			"new-assigned-to-id":   "x",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/executions/"+execution.ID.String()+"/reassign-role", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := createContext(req, rec, execution.ID.String())

		err = handler.ReassignRole(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("Error_NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		reqBody := ReassignRoleRequest{
			RoleName:          "it-ops",
			NewAssignedToType: "group",
			NewAssignedToID:   "group-2",
		}
		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/executions/"+nonExistentID.String()+"/reassign-role", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := createContext(req, rec, nonExistentID.String())

		err = handler.ReassignRole(c)
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
