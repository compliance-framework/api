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

func setupControlRelationshipTestHandler(t *testing.T) (*ControlRelationshipHandler, *gorm.DB) {
	db := setupTestDB(t)
	logger := zap.NewNop().Sugar()
	handler := NewControlRelationshipHandler(logger, db)
	return handler, db
}

func TestControlRelationshipHandler_Create(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()
	e.Validator = middleware.NewValidator()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	t.Run("Success", func(t *testing.T) {
		reqBody := CreateControlRelationshipRequest{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-2",
			ControlSource:        "NIST 800-53",
			RelationshipType:     "satisfies",
			Strength:             "primary",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/workflows/control-relationships", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = handler.Create(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, rec.Code)

		var response ControlRelationshipResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.Equal(t, "AC-2", response.Data.ControlID)
	})
}

func TestControlRelationshipHandler_List(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	rel1 := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
	}
	rel2 := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-3",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "partially_satisfies",
	}

	require.NoError(t, db.Create(rel1).Error)
	require.NoError(t, db.Create(rel2).Error)

	t.Run("FilterByWorkflowDefinitionID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/control-relationships?workflow_definition_id="+workflowDef.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ControlRelationshipListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 2)
	})

	t.Run("FilterByControlID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/control-relationships?control_id=AC-2", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handler.List(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ControlRelationshipListResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Len(t, response.Data, 1)
		assert.Equal(t, "AC-2", response.Data[0].ControlID)
	})
}

func TestControlRelationshipHandler_Get(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
	}
	require.NoError(t, db.Create(relationship).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/workflows/control-relationships/"+relationship.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(relationship.ID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ControlRelationshipResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, relationship.ID.String(), response.Data.ID.String())
	})

	t.Run("NotFound", func(t *testing.T) {
		nonExistentID := uuid.New()
		req := httptest.NewRequest(http.MethodGet, "/workflows/control-relationships/"+nonExistentID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(nonExistentID.String())

		err := handler.Get(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestControlRelationshipHandler_Update(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship).Error)

	t.Run("Success", func(t *testing.T) {
		newType := "partially_satisfies"
		reqBody := UpdateControlRelationshipRequest{
			RelationshipType: &newType,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPut, "/workflows/control-relationships/"+relationship.ID.String(), bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(relationship.ID.String())

		err = handler.Update(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ControlRelationshipResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, "partially_satisfies", response.Data.RelationshipType)
	})
}

func TestControlRelationshipHandler_Delete(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
	}
	require.NoError(t, db.Create(relationship).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/workflows/control-relationships/"+relationship.ID.String(), nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(relationship.ID.String())

		err := handler.Delete(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, rec.Code)
	})
}

func TestControlRelationshipHandler_Activate(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
		IsActive:             false,
	}
	require.NoError(t, db.Create(relationship).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/workflows/control-relationships/"+relationship.ID.String()+"/activate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(relationship.ID.String())

		err := handler.Activate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ControlRelationshipResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.True(t, response.Data.IsActive)
	})
}

func TestControlRelationshipHandler_Deactivate(t *testing.T) {
	handler, db := setupControlRelationshipTestHandler(t)
	e := echo.New()

	workflowDef := &workflows.WorkflowDefinition{
		Name:    "Test Workflow",
		Version: "1.0",
	}
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &workflows.ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
		IsActive:             true,
	}
	require.NoError(t, db.Create(relationship).Error)

	t.Run("Success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/workflows/control-relationships/"+relationship.ID.String()+"/deactivate", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("id")
		c.SetParamValues(relationship.ID.String())

		err := handler.Deactivate(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		var response ControlRelationshipResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.False(t, response.Data.IsActive)
	})
}
