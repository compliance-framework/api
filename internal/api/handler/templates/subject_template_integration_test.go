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
	SourceMode        string                                    `json:"sourceMode"`
	IdentityLabelKeys []string                                  `json:"identityLabelKeys"`
	SelectorLabels    []subjectTemplateSelectorLabelResponse    `json:"selectorLabels"`
	LabelSchema       []subjectTemplateLabelSchemaFieldResponse `json:"labelSchema"`
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

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := handlerpkg.NewEmptyAPIServices()
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

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateCRUD() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/subject-templates", map[string]any{
		"name":              "Runtime component identity",
		"type":              "component",
		"identityLabelKeys": []string{"asset_id", "cluster"},
		"sourceMode":        "runtime-derived",
		"selectorLabels": []map[string]any{
			{"key": "plugin", "value": "github"},
		},
		"labelSchema": []map[string]any{
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

	listRec, listCall := suite.authedRequest(http.MethodGet, "/api/subject-templates?type=component&sourceMode=runtime-derived&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(listRec, listCall)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed struct {
		Data []subjectTemplateAPIResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.NotEmpty(suite.T(), listed.Data)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/subject-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/subject-templates/%s", created.Data.ID), map[string]any{
		"name":              "Runtime component identity updated",
		"type":              "component",
		"identityLabelKeys": []string{"asset_id", "namespace"},
		"sourceMode":        "runtime-derived",
		"selectorLabels": []map[string]any{
			{"key": "plugin", "value": "gitlab"},
		},
		"labelSchema": []map[string]any{
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
	badCreateRec, badCreateCall := suite.authedRequest(http.MethodPost, "/api/subject-templates", map[string]any{
		"name":       "",
		"type":       "component",
		"sourceMode": "runtime-derived",
	})
	suite.server.E().ServeHTTP(badCreateRec, badCreateCall)
	require.Equal(suite.T(), http.StatusBadRequest, badCreateRec.Code)

	invalidIDRec, invalidIDCall := suite.authedRequest(http.MethodGet, "/api/subject-templates/not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidIDRec, invalidIDCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidIDRec.Code)

	missingIDRec, missingIDCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/subject-templates/%s", uuid.New()), nil)
	suite.server.E().ServeHTTP(missingIDRec, missingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, missingIDRec.Code)

	putMissingIDRec, putMissingIDCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/subject-templates/%s", uuid.New()), map[string]any{
		"name":              "Missing template",
		"type":              "component",
		"identityLabelKeys": []string{"asset_id"},
		"sourceMode":        "runtime-derived",
		"selectorLabels": []map[string]any{
			{"key": "plugin", "value": "github"},
		},
		"labelSchema": []map[string]any{
			{"key": "asset_id"},
		},
	})
	suite.server.E().ServeHTTP(putMissingIDRec, putMissingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, putMissingIDRec.Code)

	invalidTypeFilterRec, invalidTypeFilterCall := suite.authedRequest(http.MethodGet, "/api/subject-templates?type=invalid-type", nil)
	suite.server.E().ServeHTTP(invalidTypeFilterRec, invalidTypeFilterCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidTypeFilterRec.Code)

	invalidSourceModeFilterRec, invalidSourceModeFilterCall := suite.authedRequest(http.MethodGet, "/api/subject-templates?sourceMode=invalid-mode", nil)
	suite.server.E().ServeHTTP(invalidSourceModeFilterRec, invalidSourceModeFilterCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidSourceModeFilterRec.Code)
}

func (suite *SubjectTemplateApiIntegrationSuite) TestSubjectTemplateRequiresAuthentication() {
	rec, req := suite.unauthenticatedRequest(http.MethodGet, "/api/subject-templates", nil)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}
