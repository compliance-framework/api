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

func setupStepTestHandler(t *testing.T) (*WorkflowStepDefinitionHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()
	handler := NewWorkflowStepDefinitionHandler(logger, db)
	return handler, db
}

func TestWorkflowStepDefinitionHandler_Create(t *testing.T) {
	handler, db := setupStepTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	// Create a workflow definition first
	workflowDef := &workflows.WorkflowDefinition{
		Name:        "Test Workflow",
		Description: "Test workflow for steps",
		Version:     "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	t.Run("Success", func(t *testing.T) {
		reqBody := CreateWorkflowStepDefinitionRequest{
			WorkflowDefinitionID: workflowDef.ID,
			Name:                 "Security Review",
			Description:          "Conduct security review",
			ResponsibleRole:      "security_engineer",
			EvidenceRequired: []workflows.EvidenceRequirement{
				{
					Type:        "document",
					Description: "Security Report",
					Required:    true,
				},
			},
			EstimatedDuration: 120,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/steps", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response WorkflowStepDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.NotNil(t, response.Data.ID)
		assert.Equal(t, "Security Review", response.Data.Name)
		assert.Equal(t, "security_engineer", response.Data.ResponsibleRole)
		assert.Equal(t, 120, response.Data.EstimatedDuration)
	})

	t.Run("ValidationError_MissingName", func(t *testing.T) {
		reqBody := CreateWorkflowStepDefinitionRequest{
			WorkflowDefinitionID: workflowDef.ID,
			ResponsibleRole:      "security_engineer",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/steps", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("WithDependencies", func(t *testing.T) {
		// Create a step to depend on
		step1 := &workflows.WorkflowStepDefinition{
			WorkflowDefinitionID: workflowDef.ID,
			Name:                 "Step 1",
			ResponsibleRole:      "engineer",
		}
		require.NoError(t, db.Create(step1).Error)

		reqBody := CreateWorkflowStepDefinitionRequest{
			WorkflowDefinitionID: workflowDef.ID,
			Name:                 "Step 2",
			Description:          "Depends on Step 1",
			ResponsibleRole:      "engineer",
			DependsOn:            []string{step1.ID.String()},
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/steps", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)
	})
}

func TestWorkflowStepDefinitionHandler_ListByWorkflowDefinition(t *testing.T) {
	handler, db := setupStepTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	step1 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	step2 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 2",
		ResponsibleRole:      "reviewer",
	}

	require.NoError(t, db.Create(step1).Error)
	require.NoError(t, db.Create(step2).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps?workflow_definition_id="+workflowDef.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ListByWorkflowDefinition(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowStepDefinitionListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("MissingWorkflowDefinitionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ListByWorkflowDefinition(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidWorkflowDefinitionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps?workflow_definition_id=invalid", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.ListByWorkflowDefinition(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowStepDefinitionHandler_Get(t *testing.T) {
	handler, db := setupStepTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Test Step",
		Description:          "Test description",
		ResponsibleRole:      "engineer",
		EstimatedDuration:    60,
	}
	require.NoError(t, db.Create(stepDef).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps/"+stepDef.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepDef.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowStepDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, stepDef.ID.String(), response.Data.ID.String())
		assert.Equal(t, "Test Step", response.Data.Name)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("InvalidID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps/invalid-id", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("invalid-id")

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowStepDefinitionHandler_Update(t *testing.T) {
	handler, db := setupStepTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Original Name",
		Description:          "Original description",
		ResponsibleRole:      "engineer",
		EstimatedDuration:    60,
	}
	require.NoError(t, db.Create(stepDef).Error)

	t.Run("Success", func(t *testing.T) {
		newName := "Updated Name"
		newDuration := 90
		reqBody := UpdateWorkflowStepDefinitionRequest{
			Name:              &newName,
			EstimatedDuration: &newDuration,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/steps/"+stepDef.ID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepDef.ID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowStepDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", response.Data.Name)
		assert.Equal(t, 90, response.Data.EstimatedDuration)
		assert.Equal(t, "engineer", response.Data.ResponsibleRole) // Unchanged
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		newName := "Updated Name"
		reqBody := UpdateWorkflowStepDefinitionRequest{
			Name: &newName,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/steps/"+nonExistentID.String(), bytes.NewReader(body))
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

func TestWorkflowStepDefinitionHandler_Delete(t *testing.T) {
	handler, db := setupStepTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "To Be Deleted",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/workflows/steps/"+stepDef.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(stepDef.ID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify it's deleted
		var count int64
		db.Model(&workflows.WorkflowStepDefinition{}).Where("id = ?", stepDef.ID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodDelete, "/workflows/steps/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestWorkflowStepDefinitionHandler_GetDependencies(t *testing.T) {
	handler, db := setupStepTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	step1 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	step2 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 2",
		ResponsibleRole:      "engineer",
	}
	step3 := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 3 (depends on 1 and 2)",
		ResponsibleRole:      "engineer",
	}

	require.NoError(t, db.Create(step1).Error)
	require.NoError(t, db.Create(step2).Error)
	require.NoError(t, db.Create(step3).Error)

	// Add dependencies
	service := workflows.NewWorkflowStepDefinitionService(db)
	require.NoError(t, service.AddDependency(step3.ID, step1.ID))
	require.NoError(t, service.AddDependency(step3.ID, step2.ID))

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps/"+step3.ID.String()+"/dependencies", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(step3.ID.String())

		err := handler.GetDependencies(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowStepDefinitionListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("NoDependencies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/steps/"+step1.ID.String()+"/dependencies", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(step1.ID.String())

		err := handler.GetDependencies(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowStepDefinitionListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 0)
	})
}
