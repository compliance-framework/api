//go:build integration

package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	handlerpkg "github.com/compliance-framework/api/internal/api/handler"
	templaterel "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type SubjectTemplateApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

type subjectTemplateSelectorLabelResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type subjectTemplateLabelSchemaFieldResponse struct {
	Key string `json:"key"`
}

type subjectTemplateAPIResponse struct {
	ID                uuid.UUID                                 `json:"id"`
	CreatedAt         time.Time                                 `json:"createdAt"`
	UpdatedAt         time.Time                                 `json:"updatedAt"`
	Name              string                                    `json:"name"`
	Type              string                                    `json:"type"`
	SourceMode        string                                    `json:"source-mode"`
	IdentityLabelKeys []string                                  `json:"identity-label-keys"`
	SelectorLabels    []subjectTemplateSelectorLabelResponse    `json:"selector-labels"`
	LabelSchema       []subjectTemplateLabelSchemaFieldResponse `json:"label-schema"`
}

type subjectTemplateDataEnvelope struct {
	Data subjectTemplateAPIResponse `json:"data"`
}

func TestSubjectTemplateAPI(t *testing.T) {
	suite.Run(t, new(SubjectTemplateApiIntegrationSuite))
}

func (suite *SubjectTemplateApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	suite.Config.StrictDisablePublicAgentEndpoints = true
	suite.setupServer()
}

func (suite *SubjectTemplateApiIntegrationSuite) setupServer() {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &handlerpkg.APIServices{}
	handlerpkg.RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, services)
}

func (suite *SubjectTemplateApiIntegrationSuite) authedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	payload := []byte{}
	if body != nil {
		data, marshalErr := json.Marshal(body)
		suite.Require().NoError(marshalErr)
		payload = data
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	return rec, req
}

func (suite *SubjectTemplateApiIntegrationSuite) unauthenticatedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	payload := []byte{}
	if body != nil {
		data, marshalErr := json.Marshal(body)
		suite.Require().NoError(marshalErr)
		payload = data
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	return rec, req
}

func (suite *SubjectTemplateApiIntegrationSuite) agentRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	agent, err := suite.CreateAgent("subject-template-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "subject-template-key")
	suite.Require().NoError(err)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	payload := []byte{}
	if body != nil {
		data, marshalErr := json.Marshal(body)
		suite.Require().NoError(marshalErr)
		payload = data
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	return rec, req
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateCRUD() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/subject-templates", map[string]any{
		"name":                "Runtime component identity",
		"type":                "component",
		"identity-label-keys": []string{"asset_id", "cluster"},
		"source-mode":         "runtime-derived",
		"selector-labels": []map[string]any{
			{"key": "plugin", "value": "github"},
		},
		"label-schema": []map[string]any{
			{"key": "asset_id", "description": "Unique asset ID"},
			{"key": "cluster", "description": "Cluster"},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created subjectTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEqual(suite.T(), uuid.Nil, created.Data.ID)
	require.False(suite.T(), created.Data.CreatedAt.IsZero())
	require.False(suite.T(), created.Data.UpdatedAt.IsZero())
	require.Equal(suite.T(), "component", created.Data.Type)
	require.Equal(suite.T(), "runtime-derived", created.Data.SourceMode)
	require.Len(suite.T(), created.Data.SelectorLabels, 1)
	require.Len(suite.T(), created.Data.LabelSchema, 2)

	listRec, listCall := suite.authedRequest(http.MethodGet, "/api/admin/subject-templates?type=component&source-mode=runtime-derived&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(listRec, listCall)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed struct {
		Data []subjectTemplateAPIResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.NotEmpty(suite.T(), listed.Data)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/subject-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/subject-templates/%s", created.Data.ID), map[string]any{
		"name":                "Runtime component identity updated",
		"type":                "component",
		"identity-label-keys": []string{"asset_id", "namespace"},
		"source-mode":         "runtime-derived",
		"selector-labels": []map[string]any{
			{"key": "plugin", "value": "gitlab"},
		},
		"label-schema": []map[string]any{
			{"key": "asset_id", "description": "Unique asset ID"},
			{"key": "namespace", "description": "Namespace"},
		},
	})
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated subjectTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.Equal(suite.T(), "Runtime component identity updated", updated.Data.Name)
	require.Equal(suite.T(), []string{"asset_id", "namespace"}, updated.Data.IdentityLabelKeys)
	require.Len(suite.T(), updated.Data.SelectorLabels, 1)
	require.Equal(suite.T(), "gitlab", updated.Data.SelectorLabels[0].Value)
	require.Len(suite.T(), updated.Data.LabelSchema, 2)

	var selectorCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.SubjectTemplateSelectorLabel{}).Where("subject_template_id = ?", created.Data.ID).Count(&selectorCount).Error)
	require.Equal(suite.T(), int64(1), selectorCount)

	var schemaCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.SubjectTemplateLabelSchemaField{}).Where("subject_template_id = ?", created.Data.ID).Count(&schemaCount).Error)
	require.Equal(suite.T(), int64(2), schemaCount)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateValidationAndNotFound() {
	badCreateRec, badCreateCall := suite.authedRequest(http.MethodPost, "/api/admin/subject-templates", map[string]any{
		"name":        "",
		"type":        "component",
		"source-mode": "runtime-derived",
	})
	suite.server.E().ServeHTTP(badCreateRec, badCreateCall)
	require.Equal(suite.T(), http.StatusBadRequest, badCreateRec.Code)

	invalidIDRec, invalidIDCall := suite.authedRequest(http.MethodGet, "/api/admin/subject-templates/not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidIDRec, invalidIDCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidIDRec.Code)

	missingIDRec, missingIDCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/subject-templates/%s", uuid.New()), nil)
	suite.server.E().ServeHTTP(missingIDRec, missingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, missingIDRec.Code)

	putMissingIDRec, putMissingIDCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/subject-templates/%s", uuid.New()), map[string]any{
		"name":                "Missing template",
		"type":                "component",
		"identity-label-keys": []string{"asset_id"},
		"source-mode":         "runtime-derived",
		"selector-labels": []map[string]any{
			{"key": "plugin", "value": "github"},
		},
		"label-schema": []map[string]any{
			{"key": "asset_id"},
		},
	})
	suite.server.E().ServeHTTP(putMissingIDRec, putMissingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, putMissingIDRec.Code)

	invalidTypeFilterRec, invalidTypeFilterCall := suite.authedRequest(http.MethodGet, "/api/admin/subject-templates?type=invalid-type", nil)
	suite.server.E().ServeHTTP(invalidTypeFilterRec, invalidTypeFilterCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidTypeFilterRec.Code)

	invalidSourceModeFilterRec, invalidSourceModeFilterCall := suite.authedRequest(http.MethodGet, "/api/admin/subject-templates?source-mode=invalid-mode", nil)
	suite.server.E().ServeHTTP(invalidSourceModeFilterRec, invalidSourceModeFilterCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidSourceModeFilterRec.Code)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateRequiresAuthentication() {
	rec, req := suite.unauthenticatedRequest(http.MethodGet, "/api/admin/subject-templates", nil)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}

type batchSubjectTemplateResult struct {
	Data struct {
		Created []subjectTemplateAPIResponse `json:"created"`
		Updated []subjectTemplateAPIResponse `json:"updated"`
		Deleted []uuid.UUID                  `json:"deleted"`
	} `json:"data"`
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateBatchUpsertCreateAndUpdate() {
	// Step 1 — batch creates two templates scoped to "batch-plugin". Both IDs supplied by caller.
	firstID := uuid.New()
	secondID := uuid.New()
	batchReq := map[string]any{
		"plugin-id": "batch-plugin",
		"templates": []map[string]any{
			{
				"id":                  firstID.String(),
				"name":                "Batch subject one",
				"type":                "component",
				"source-mode":         "runtime-derived",
				"identity-label-keys": []string{"asset_id"},
				"selector-labels": []map[string]any{
					{"key": "_plugin", "value": "batch-plugin"},
				},
				"label-schema": []map[string]any{
					{"key": "asset_id", "description": "Unique asset ID"},
				},
			},
			{
				"id":                  secondID.String(),
				"name":                "Batch subject two",
				"type":                "component",
				"source-mode":         "runtime-derived",
				"identity-label-keys": []string{"cluster"},
				"selector-labels": []map[string]any{
					{"key": "_plugin", "value": "batch-plugin"},
				},
				"label-schema": []map[string]any{
					{"key": "cluster", "description": "Cluster name"},
				},
			},
		},
	}

	rec, req := suite.agentRequest(http.MethodPost, "/api/agent/subject-templates/batch", batchReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)

	var result1 batchSubjectTemplateResult
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &result1))
	require.Len(suite.T(), result1.Data.Created, 2)
	require.Empty(suite.T(), result1.Data.Updated)
	require.Empty(suite.T(), result1.Data.Deleted)
	// Confirm both explicit IDs were honoured.
	var foundFirst, foundSecond bool
	for _, row := range result1.Data.Created {
		if row.ID == firstID {
			foundFirst = true
			require.Equal(suite.T(), "Batch subject one", row.Name)
		}
		if row.ID == secondID {
			foundSecond = true
		}
	}
	require.True(suite.T(), foundFirst, "first template should be in created list")
	require.True(suite.T(), foundSecond, "second template should be in created list")

	// Step 2 — update first, drop second (deleted), add a third.
	thirdID := uuid.New()
	batchReq2 := map[string]any{
		"plugin-id": "batch-plugin",
		"templates": []map[string]any{
			{
				"id":                  firstID.String(),
				"name":                "Batch subject one updated",
				"type":                "component",
				"source-mode":         "runtime-derived",
				"identity-label-keys": []string{"asset_id", "region"},
				"selector-labels": []map[string]any{
					{"key": "_plugin", "value": "batch-plugin"},
				},
				"label-schema": []map[string]any{
					{"key": "asset_id", "description": "Unique asset ID"},
					{"key": "region", "description": "Cloud region"},
				},
			},
			{
				"id":                  thirdID.String(),
				"name":                "Batch subject three",
				"type":                "component",
				"source-mode":         "runtime-derived",
				"identity-label-keys": []string{"namespace"},
				"selector-labels": []map[string]any{
					{"key": "_plugin", "value": "batch-plugin"},
				},
				"label-schema": []map[string]any{
					{"key": "namespace", "description": "Kubernetes namespace"},
				},
			},
		},
	}

	rec2, req2 := suite.agentRequest(http.MethodPost, "/api/agent/subject-templates/batch", batchReq2)
	suite.server.E().ServeHTTP(rec2, req2)
	require.Equal(suite.T(), http.StatusOK, rec2.Code)

	var result2 batchSubjectTemplateResult
	require.NoError(suite.T(), json.Unmarshal(rec2.Body.Bytes(), &result2))
	require.Len(suite.T(), result2.Data.Updated, 1, "first template should be updated")
	require.Len(suite.T(), result2.Data.Created, 1, "third template should be created")
	require.Len(suite.T(), result2.Data.Deleted, 1, "second template should be deleted")
	require.Equal(suite.T(), secondID, result2.Data.Deleted[0])
	require.Equal(suite.T(), firstID, result2.Data.Updated[0].ID)
	require.Equal(suite.T(), "Batch subject one updated", result2.Data.Updated[0].Name)
	require.Len(suite.T(), result2.Data.Updated[0].LabelSchema, 2)

	// Confirm selector labels were replaced correctly for the updated template.
	var selectorCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.SubjectTemplateSelectorLabel{}).
		Where("subject_template_id = ?", firstID).Count(&selectorCount).Error)
	require.Equal(suite.T(), int64(1), selectorCount)

	// Step 3 — confirm second template is gone.
	var count int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.SubjectTemplate{}).Where("id = ?", secondID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateBatchUpsertEmptyPayloadDeletesAll() {
	// Seed two templates via admin endpoint.
	for i, name := range []string{"Delete subject one", "Delete subject two"} {
		_ = i
		r, c := suite.authedRequest(http.MethodPost, "/api/admin/subject-templates", map[string]any{
			"name":                name,
			"type":                "component",
			"source-mode":         "runtime-derived",
			"identity-label-keys": []string{"asset_id"},
			"selector-labels": []map[string]any{
				{"key": "_plugin", "value": "delete-plugin"},
			},
			"label-schema": []map[string]any{
				{"key": "asset_id", "description": "ID"},
			},
		})
		suite.server.E().ServeHTTP(r, c)
		require.Equal(suite.T(), http.StatusCreated, r.Code)
	}

	// Send empty template list — both should be deleted.
	rec, req := suite.agentRequest(http.MethodPost, "/api/agent/subject-templates/batch", map[string]any{
		"plugin-id": "delete-plugin",
		"templates": []map[string]any{},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)

	var result batchSubjectTemplateResult
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &result))
	require.Empty(suite.T(), result.Data.Created)
	require.Empty(suite.T(), result.Data.Updated)
	require.Len(suite.T(), result.Data.Deleted, 2)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateBatchUpsertMissingIDReturns400() {
	rec, req := suite.agentRequest(http.MethodPost, "/api/agent/subject-templates/batch", map[string]any{
		"plugin-id": "batch-plugin",
		"templates": []map[string]any{
			{
				"name":        "Missing ID subject",
				"type":        "component",
				"source-mode": "runtime-derived",
				"selector-labels": []map[string]any{
					{"key": "_plugin", "value": "batch-plugin"},
				},
			},
		},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)
	require.Contains(suite.T(), rec.Body.String(), "id is required")
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateBatchUpsertValidationError() {
	rec, req := suite.agentRequest(http.MethodPost, "/api/agent/subject-templates/batch", map[string]any{
		"plugin-id": "batch-plugin",
		"templates": []map[string]any{
			{
				"id":          uuid.New().String(),
				"name":        "",
				"type":        "component",
				"source-mode": "runtime-derived",
				"selector-labels": []map[string]any{
					{"key": "_plugin", "value": "batch-plugin"},
				},
			},
		},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateBatchUpsertIsPublicWhenUnsafeFlagEnabled() {
	suite.Config.StrictDisablePublicAgentEndpoints = false
	suite.setupServer()

	rec, req := suite.unauthenticatedRequest(http.MethodPost, "/api/agent/subject-templates/batch", map[string]any{
		"plugin-id": "batch-plugin",
		"templates": []map[string]any{},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateBatchUpsertRequiresAgentAuthWhenUnsafeDisabled() {
	rec, req := suite.unauthenticatedRequest(http.MethodPost, "/api/agent/subject-templates/batch", map[string]any{
		"plugin-id": "batch-plugin",
		"templates": []map[string]any{},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}
