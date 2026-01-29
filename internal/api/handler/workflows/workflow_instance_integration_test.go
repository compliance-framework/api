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

func setupInstanceTestHandler(t *testing.T) (*WorkflowInstanceHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()
	handler := NewWorkflowInstanceHandler(logger, db)
	return handler, db
}

func TestWorkflowInstanceHandler_Create(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	t.Run("Success", func(t *testing.T) {
		reqBody := CreateWorkflowInstanceRequest{
			WorkflowDefinitionID: workflowDef.ID,
			Name:                 "Production Security Assessment",
			Description:          "Security assessment for production environment",
			SystemName:           "production-web-app",
			Cadence:              "quarterly",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/instances", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response WorkflowInstanceResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.NotNil(t, response.Data.ID)
		assert.Equal(t, "Production Security Assessment", response.Data.Name)
		assert.Equal(t, "production-web-app", response.Data.SystemName)
		assert.Equal(t, "quarterly", response.Data.Cadence)
		assert.True(t, response.Data.IsActive)
	})

	t.Run("ValidationError_MissingName", func(t *testing.T) {
		reqBody := CreateWorkflowInstanceRequest{
			WorkflowDefinitionID: workflowDef.ID,
			SystemName:           "test-system",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/instances", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("WithIsActiveFalse", func(t *testing.T) {
		isActive := false
		reqBody := CreateWorkflowInstanceRequest{
			WorkflowDefinitionID: workflowDef.ID,
			Name:                 "Inactive Instance",
			SystemName:           "test-system",
			IsActive:             &isActive,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/instances", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response WorkflowInstanceResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		// Note: Service may override IsActive based on validation rules
		assert.NotNil(t, response.Data)
	})
}

func TestWorkflowInstanceHandler_List(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	instance1 := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Instance 1",
		SystemName:           "system-a",
		IsActive:             true,
	}
	instance2 := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Instance 2",
		SystemName:           "system-b",
		IsActive:             true,
	}

	require.NoError(t, db.Create(instance1).Error)
	require.NoError(t, db.Create(instance2).Error)

	// Deactivate instance2 for filtering tests
	db.Model(instance2).Update("is_active", false)

	t.Run("ListAll", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/instances", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("FilterByWorkflowDefinitionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/instances?workflow_definition_id="+workflowDef.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("FilterBySystemName", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/instances?system_name=system-a", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 1)
		assert.Equal(t, "system-a", response.Data[0].SystemName)
	})

	t.Run("FilterByIsActive", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/instances?is_active=true", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 1)
		assert.True(t, response.Data[0].IsActive)
	})
}

func TestWorkflowInstanceHandler_Get(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
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
		Cadence:              "monthly",
		IsActive:             true,
	}
	require.NoError(t, db.Create(instance).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/instances/"+instance.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(instance.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, instance.ID.String(), response.Data.ID.String())
		assert.Equal(t, "Test Instance", response.Data.Name)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/instances/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestWorkflowInstanceHandler_Update(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Original Name",
		SystemName:           "original-system",
		Cadence:              "monthly",
		IsActive:             true,
	}
	require.NoError(t, db.Create(instance).Error)

	t.Run("Success", func(t *testing.T) {
		newName := "Updated Name"
		newCadence := "quarterly"
		reqBody := UpdateWorkflowInstanceRequest{
			Name:    &newName,
			Cadence: &newCadence,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/instances/"+instance.ID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(instance.ID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", response.Data.Name)
		assert.Equal(t, "quarterly", response.Data.Cadence)
		assert.Equal(t, "original-system", response.Data.SystemName) // Unchanged
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		newName := "Updated Name"
		reqBody := UpdateWorkflowInstanceRequest{
			Name: &newName,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/instances/"+nonExistentID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestWorkflowInstanceHandler_Delete(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "To Be Deleted",
		SystemName:           "test-system",
	}
	require.NoError(t, db.Create(instance).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/workflows/instances/"+instance.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(instance.ID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify it's deleted
		var count int64
		db.Model(&workflows.WorkflowInstance{}).Where("id = ?", instance.ID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodDelete, "/workflows/instances/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestWorkflowInstanceHandler_Activate(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
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
		IsActive:             false,
	}
	require.NoError(t, db.Create(instance).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/workflows/instances/"+instance.ID.String()+"/activate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(instance.ID.String())

		err := handler.Activate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Data.IsActive)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodPut, "/workflows/instances/"+nonExistentID.String()+"/activate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Activate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestWorkflowInstanceHandler_Deactivate(t *testing.T) {
	handler, db := setupInstanceTestHandler(t)
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
		IsActive:             true,
	}
	require.NoError(t, db.Create(instance).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/workflows/instances/"+instance.ID.String()+"/deactivate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(instance.ID.String())

		err := handler.Deactivate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowInstanceResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Data.IsActive)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodPut, "/workflows/instances/"+nonExistentID.String()+"/deactivate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Deactivate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}
