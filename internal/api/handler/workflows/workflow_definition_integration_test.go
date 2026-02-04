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

func setupTestHandler(t *testing.T) (*WorkflowDefinitionHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()
	handler := NewWorkflowDefinitionHandler(logger, db)
	return handler, db
}

func TestWorkflowDefinitionHandler_Create(t *testing.T) {
	handler, _ := setupTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	t.Run("Success", func(t *testing.T) {
		reqBody := CreateWorkflowDefinitionRequest{
			Name:             "Security Assessment Workflow",
			Description:      "Quarterly security assessment process",
			Version:          "1.0",
			SuggestedCadence: "quarterly",
			EvidenceRequired: `["vulnerability_scan", "penetration_test"]`,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/definitions", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response WorkflowDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.NotNil(t, response.Data.ID)
		assert.Equal(t, "Security Assessment Workflow", response.Data.Name)
		assert.Equal(t, "Quarterly security assessment process", response.Data.Description)
		assert.Equal(t, "1.0", response.Data.Version)
		assert.Equal(t, "quarterly", response.Data.SuggestedCadence)
	})

	t.Run("ValidationError_MissingName", func(t *testing.T) {
		reqBody := CreateWorkflowDefinitionRequest{
			Description: "Missing name",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/definitions", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/workflows/definitions", bytes.NewReader([]byte("invalid json")))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowDefinitionHandler_List(t *testing.T) {
	handler, db := setupTestHandler(t)
	e := echo.New()

	definition1 := &workflows.WorkflowDefinition{
		Name:             "Workflow 1",
		Description:      "First workflow",
		Version:          "1.0",
		SuggestedCadence: "monthly",
	}
	definition2 := &workflows.WorkflowDefinition{
		Name:             "Workflow 2",
		Description:      "Second workflow",
		Version:          "1.0",
		SuggestedCadence: "quarterly",
	}

	require.NoError(t, db.Create(definition1).Error)
	require.NoError(t, db.Create(definition2).Error)

	req := httptest.NewRequest(http.MethodGet, "/workflows/definitions", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.List(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response WorkflowDefinitionListResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Len(t, response.Data, 2)
	assert.Equal(t, "Workflow 1", response.Data[0].Name)
	assert.Equal(t, "Workflow 2", response.Data[1].Name)
}

func TestWorkflowDefinitionHandler_Get(t *testing.T) {
	handler, db := setupTestHandler(t)
	e := echo.New()

	definition := &workflows.WorkflowDefinition{
		Name:             "Test Workflow",
		Description:      "Test description",
		Version:          "1.0",
		SuggestedCadence: "weekly",
	}
	require.NoError(t, db.Create(definition).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/definitions/"+definition.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(definition.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, definition.ID.String(), response.Data.ID.String())
		assert.Equal(t, "Test Workflow", response.Data.Name)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/definitions/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("InvalidID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/definitions/invalid-id", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("invalid-id")

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowDefinitionHandler_Update(t *testing.T) {
	handler, db := setupTestHandler(t)
	e := echo.New()

	definition := &workflows.WorkflowDefinition{
		Name:             "Original Name",
		Description:      "Original description",
		Version:          "1.0",
		SuggestedCadence: "monthly",
	}
	require.NoError(t, db.Create(definition).Error)

	t.Run("Success", func(t *testing.T) {
		newName := "Updated Name"
		newDescription := "Updated description"
		reqBody := UpdateWorkflowDefinitionRequest{
			Name:        &newName,
			Description: &newDescription,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/definitions/"+definition.ID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(definition.ID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", response.Data.Name)
		assert.Equal(t, "Updated description", response.Data.Description)
		assert.Equal(t, "1.0", response.Data.Version) // Unchanged
	})

	t.Run("PartialUpdate", func(t *testing.T) {
		newVersion := "2.0"
		reqBody := UpdateWorkflowDefinitionRequest{
			Version: &newVersion,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/definitions/"+definition.ID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(definition.ID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response WorkflowDefinitionResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "2.0", response.Data.Version)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		newName := "Updated Name"
		reqBody := UpdateWorkflowDefinitionRequest{
			Name: &newName,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/definitions/"+nonExistentID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("InvalidID", func(t *testing.T) {
		newName := "Updated Name"
		reqBody := UpdateWorkflowDefinitionRequest{
			Name: &newName,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/definitions/invalid-id", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("invalid-id")

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestWorkflowDefinitionHandler_Delete(t *testing.T) {
	handler, db := setupTestHandler(t)
	e := echo.New()

	definition := &workflows.WorkflowDefinition{
		Name:             "To Be Deleted",
		Description:      "This will be deleted",
		Version:          "1.0",
		SuggestedCadence: "monthly",
	}
	require.NoError(t, db.Create(definition).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/workflows/definitions/"+definition.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(definition.ID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify it's deleted
		var count int64
		db.Model(&workflows.WorkflowDefinition{}).Where("id = ?", definition.ID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodDelete, "/workflows/definitions/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("InvalidID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/workflows/definitions/invalid-id", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues("invalid-id")

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
