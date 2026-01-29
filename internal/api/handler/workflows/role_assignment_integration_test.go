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

func setupRoleAssignmentTestHandler(t *testing.T) (*RoleAssignmentHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()
	handler := NewRoleAssignmentHandler(logger, db)
	return handler, db
}

func TestRoleAssignmentHandler_Create(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	t.Run("Success", func(t *testing.T) {
		reqBody := CreateRoleAssignmentRequest{
			WorkflowInstanceID: instance.ID,
			RoleName:           "engineer",
			AssignedToType:     "user",
			AssignedToID:       "user-123",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/role-assignments", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response RoleAssignmentResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, "engineer", response.Data.RoleName)
		assert.Equal(t, "user-123", response.Data.AssignedToID)
	})
}

func TestRoleAssignmentHandler_List(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	assignment1 := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "user-123",
	}
	assignment2 := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user-456",
	}

	require.NoError(t, db.Create(assignment1).Error)
	require.NoError(t, db.Create(assignment2).Error)

	t.Run("ListAll", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/role-assignments?workflow_instance_id="+instance.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response RoleAssignmentListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("FilterByRole", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/role-assignments?workflow_instance_id="+instance.ID.String()+"&role_name=engineer", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response RoleAssignmentListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 1)
		assert.Equal(t, "engineer", response.Data[0].RoleName)
	})

	t.Run("MissingWorkflowInstanceID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/role-assignments", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestRoleAssignmentHandler_Get(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	assignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "user-123",
	}
	require.NoError(t, db.Create(assignment).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/role-assignments/"+assignment.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(assignment.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response RoleAssignmentResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, assignment.ID.String(), response.Data.ID.String())
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/role-assignments/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestRoleAssignmentHandler_Update(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	assignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "user-123",
	}
	require.NoError(t, db.Create(assignment).Error)

	t.Run("Success", func(t *testing.T) {
		newAssignedToID := "user-456"
		reqBody := UpdateRoleAssignmentRequest{
			AssignedToID: &newAssignedToID,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/role-assignments/"+assignment.ID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(assignment.ID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response RoleAssignmentResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "user-456", response.Data.AssignedToID)
	})
}

func TestRoleAssignmentHandler_Delete(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	assignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "user-123",
	}
	require.NoError(t, db.Create(assignment).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/workflows/role-assignments/"+assignment.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(assignment.ID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}

func TestRoleAssignmentHandler_Activate(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	assignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "user-123",
		IsActive:           false,
	}
	require.NoError(t, db.Create(assignment).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/workflows/role-assignments/"+assignment.ID.String()+"/activate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(assignment.ID.String())

		err := handler.Activate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response RoleAssignmentResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Data.IsActive)
	})
}

func TestRoleAssignmentHandler_Deactivate(t *testing.T) {
	handler, db := setupRoleAssignmentTestHandler(t)
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

	assignment := &workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     "user",
		AssignedToID:       "user-123",
		IsActive:           true,
	}
	require.NoError(t, db.Create(assignment).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/workflows/role-assignments/"+assignment.ID.String()+"/deactivate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(assignment.ID.String())

		err := handler.Deactivate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response RoleAssignmentResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Data.IsActive)
	})
}
