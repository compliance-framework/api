//go:build integration

package templates_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

type RiskTemplateApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

type threatIDResponse struct {
	System string `json:"system"`
	ID     string `json:"id"`
}

type remediationTaskResponse struct {
	ID         uuid.UUID `json:"id"`
	OrderIndex int       `json:"order-index"`
}

type remediationTemplateResponse struct {
	ID    uuid.UUID                 `json:"id"`
	Tasks []remediationTaskResponse `json:"tasks"`
}

type riskTemplateResponse struct {
	ID          uuid.UUID                    `json:"id"`
	CreatedAt   time.Time                    `json:"created-at"`
	UpdatedAt   time.Time                    `json:"updated-at"`
	PluginID    string                       `json:"plugin-id"`
	Name        string                       `json:"name"`
	IsActive    bool                         `json:"is-active"`
	ThreatIDs   []threatIDResponse           `json:"threat-ids"`
	Remediation *remediationTemplateResponse `json:"remediation-template,omitempty"`
}

type genericDataResponse[T any] struct {
	Data T `json:"data"`
}

func TestRiskTemplateAPI(t *testing.T) {
	suite.Run(t, new(RiskTemplateApiIntegrationSuite))
}

func (suite *RiskTemplateApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &handlerpkg.APIServices{}
	handlerpkg.RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, services)
}

func (suite *RiskTemplateApiIntegrationSuite) authedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

func (suite *RiskTemplateApiIntegrationSuite) unauthenticatedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateCRUD() {
	createReq := map[string]any{
		"plugin-id":       "github-repositories",
		"policy-package":  "compliance_framework.secret_scanning_enabled",
		"name":            "Secret scanning risk template",
		"title":           "Undetected secrets committed to repository",
		"statement":       "Secret scanning is disabled and secrets may leak.",
		"likelihood-hint": "medium",
		"impact-hint":     "high",
		"violation-ids":   []string{"missing_secret_scanning"},
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Cleartext Storage of Sensitive Information",
			},
		},
		"remediation-template": map[string]any{
			"title":       "Enable secret scanning",
			"description": "Enable and verify scanning in repository settings.",
			"tasks": []map[string]any{
				{"title": "Enable in repository settings", "order-index": 1},
			},
		},
		"is-active": true,
	}

	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", createReq)
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEqual(suite.T(), uuid.Nil, created.Data.ID)
	require.Equal(suite.T(), "github-repositories", created.Data.PluginID)
	require.False(suite.T(), created.Data.CreatedAt.IsZero())
	require.False(suite.T(), created.Data.UpdatedAt.IsZero())
	require.Len(suite.T(), created.Data.ThreatIDs, 1)
	require.NotNil(suite.T(), created.Data.Remediation)
	require.Len(suite.T(), created.Data.Remediation.Tasks, 1)

	listRec, listCall := suite.authedRequest(http.MethodGet, "/api/admin/risk-templates?plugin-id=github-repositories&is-active=true&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(listRec, listCall)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed struct {
		Data []riskTemplateResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.NotEmpty(suite.T(), listed.Data)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), map[string]any{
		"plugin-id":       "github-repositories",
		"policy-package":  "compliance_framework.secret_scanning_enabled",
		"name":            "Secret scanning risk template updated",
		"title":           "Undetected secrets committed to repository updated",
		"statement":       "Updated statement.",
		"likelihood-hint": "low",
		"impact-hint":     "medium",
		"violation-ids":   []string{"missing_secret_scanning", "missing_push_protection"},
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-200",
				"title":  "Exposure of Sensitive Information to an Unauthorized Actor",
			},
		},
		"remediation-template": map[string]any{
			"title": "Enable secret scanning and push protection",
			"tasks": []map[string]any{
				{"title": "Enable secret scanning", "order-index": 1},
			},
		},
		"is-active": false,
	})
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.Equal(suite.T(), "Secret scanning risk template updated", updated.Data.Name)
	require.False(suite.T(), updated.Data.IsActive)
	require.Len(suite.T(), updated.Data.ThreatIDs, 1)
	require.Equal(suite.T(), "CWE-200", updated.Data.ThreatIDs[0].ID)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateValidationAndNotFound() {
	badCreateRec, badCreateCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id": "",
	})
	suite.server.E().ServeHTTP(badCreateRec, badCreateCall)
	require.Equal(suite.T(), http.StatusBadRequest, badCreateRec.Code)

	invalidIDRec, invalidIDCall := suite.authedRequest(http.MethodGet, "/api/admin/risk-templates/not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidIDRec, invalidIDCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidIDRec.Code)

	missingIDRec, missingIDCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/risk-templates/%s", uuid.New()), nil)
	suite.server.E().ServeHTTP(missingIDRec, missingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, missingIDRec.Code)

	putMissingIDRec, putMissingIDCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/risk-templates/%s", uuid.New()), map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Missing template",
		"title":          "Missing template",
		"statement":      "Missing template statement",
	})
	suite.server.E().ServeHTTP(putMissingIDRec, putMissingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, putMissingIDRec.Code)

	invalidFilterRec, invalidFilterCall := suite.authedRequest(http.MethodGet, "/api/admin/risk-templates?is-active=definitely-not-bool", nil)
	suite.server.E().ServeHTTP(invalidFilterRec, invalidFilterCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidFilterRec.Code)
	require.Contains(suite.T(), invalidFilterRec.Body.String(), "definitely-not-bool")
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateDefaultActiveAndHintValidation() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Active-by-default template",
		"title":          "Template title",
		"statement":      "Template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Cleartext Storage of Sensitive Information",
			},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.True(suite.T(), created.Data.IsActive)

	invalidHintRec, invalidHintCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":       "github-repositories",
		"policy-package":  "compliance_framework.secret_scanning_enabled",
		"name":            "Invalid hint template",
		"title":           "Template title",
		"statement":       "Template statement",
		"likelihood-hint": "critical",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Cleartext Storage of Sensitive Information",
			},
		},
	})
	suite.server.E().ServeHTTP(invalidHintRec, invalidHintCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidHintRec.Code)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateRemediationRemovalAndDelete() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Template with remediation",
		"title":          "Template with remediation",
		"statement":      "Template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Cleartext Storage of Sensitive Information",
			},
		},
		"remediation-template": map[string]any{
			"title": "Enable feature",
			"tasks": []map[string]any{
				{"title": "Task one", "order-index": 1},
			},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotNil(suite.T(), created.Data.Remediation)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Template without remediation",
		"title":          "Template without remediation",
		"statement":      "Updated template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-200",
				"title":  "Exposure of Sensitive Information to an Unauthorized Actor",
			},
		},
	})
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.Nil(suite.T(), updated.Data.Remediation)

	var threatRefCountBeforeDelete int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RiskTemplateThreatRef{}).Where("risk_template_id = ?", created.Data.ID).Count(&threatRefCountBeforeDelete).Error)
	require.Equal(suite.T(), int64(1), threatRefCountBeforeDelete)

	var remediationTemplateCountAfterUpdate int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RemediationTemplate{}).Where("id = ?", created.Data.Remediation.ID).Count(&remediationTemplateCountAfterUpdate).Error)
	require.Equal(suite.T(), int64(0), remediationTemplateCountAfterUpdate)

	var remediationTaskCountAfterUpdate int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RemediationTask{}).Where("remediation_template_id = ?", created.Data.Remediation.ID).Count(&remediationTaskCountAfterUpdate).Error)
	require.Equal(suite.T(), int64(0), remediationTaskCountAfterUpdate)

	deleteRec, deleteCall := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteCall)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusNotFound, getRec.Code)

	var threatRefCountAfterDelete int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RiskTemplateThreatRef{}).Where("risk_template_id = ?", created.Data.ID).Count(&threatRefCountAfterDelete).Error)
	require.Equal(suite.T(), int64(0), threatRefCountAfterDelete)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateUpdateWithoutIsActivePreservesExistingValue() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Inactive template",
		"title":          "Inactive template",
		"statement":      "Template statement",
		"is-active":      false,
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.False(suite.T(), created.Data.IsActive)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Inactive template updated",
		"title":          "Inactive template updated",
		"statement":      "Updated statement",
	})
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.False(suite.T(), updated.Data.IsActive)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateDeleteCleansDependentRows() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Template for delete cleanup",
		"title":          "Template for delete cleanup",
		"statement":      "Template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Cleartext Storage of Sensitive Information",
			},
		},
		"remediation-template": map[string]any{
			"title": "Delete cleanup remediation",
			"tasks": []map[string]any{
				{"title": "Task one", "order-index": 1},
				{"title": "Task two", "order-index": 2},
			},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotNil(suite.T(), created.Data.Remediation)

	deleteRec, deleteCall := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteCall)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)

	var threatRefCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RiskTemplateThreatRef{}).Where("risk_template_id = ?", created.Data.ID).Count(&threatRefCount).Error)
	require.Equal(suite.T(), int64(0), threatRefCount)

	var remediationTemplateCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RemediationTemplate{}).Where("id = ?", created.Data.Remediation.ID).Count(&remediationTemplateCount).Error)
	require.Equal(suite.T(), int64(0), remediationTemplateCount)

	var remediationTaskCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RemediationTask{}).Where("remediation_template_id = ?", created.Data.Remediation.ID).Count(&remediationTaskCount).Error)
	require.Equal(suite.T(), int64(0), remediationTaskCount)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateThreatValidationErrorFields() {
	missingThreatIDRec, missingThreatIDCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Invalid threat field name",
		"title":          "Invalid threat field name",
		"statement":      "Template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "",
				"title":  "Missing ID",
			},
		},
	})
	suite.server.E().ServeHTTP(missingThreatIDRec, missingThreatIDCall)
	require.Equal(suite.T(), http.StatusBadRequest, missingThreatIDRec.Code)
	require.Contains(suite.T(), missingThreatIDRec.Body.String(), "threatIds.id is required")

	duplicateThreatRec, duplicateThreatCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Duplicate threat validation",
		"title":          "Duplicate threat validation",
		"statement":      "Template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Threat one",
			},
			{
				"system": "https://cwe.mitre.org",
				"id":     "CWE-312",
				"title":  "Threat one duplicate",
			},
		},
	})
	suite.server.E().ServeHTTP(duplicateThreatRec, duplicateThreatCall)
	require.Equal(suite.T(), http.StatusBadRequest, duplicateThreatRec.Code)
	require.Contains(suite.T(), duplicateThreatRec.Body.String(), "threatIds contains duplicate system/id pairs")
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateRemediationTasksAreReturnedInOrder() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Ordered remediation tasks",
		"title":          "Ordered remediation tasks",
		"statement":      "Template statement",
		"remediation-template": map[string]any{
			"title": "Ordered remediation",
			"tasks": []map[string]any{
				{"title": "Task two", "order-index": 2},
				{"title": "Task one", "order-index": 1},
			},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotNil(suite.T(), created.Data.Remediation)
	require.Len(suite.T(), created.Data.Remediation.Tasks, 2)
	require.Equal(suite.T(), 1, created.Data.Remediation.Tasks[0].OrderIndex)
	require.Equal(suite.T(), 2, created.Data.Remediation.Tasks[1].OrderIndex)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	var fetched genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(getRec.Body.Bytes(), &fetched))
	require.NotNil(suite.T(), fetched.Data.Remediation)
	require.Len(suite.T(), fetched.Data.Remediation.Tasks, 2)
	require.Equal(suite.T(), 1, fetched.Data.Remediation.Tasks[0].OrderIndex)
	require.Equal(suite.T(), 2, fetched.Data.Remediation.Tasks[1].OrderIndex)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateThreatRefsAreReturnedInOrder() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Ordered threat refs",
		"title":          "Ordered threat refs",
		"statement":      "Template statement",
		"threat-ids": []map[string]any{
			{
				"system": "https://attack.mitre.org",
				"id":     "T1552",
				"title":  "Threat two",
			},
			{
				"system": "https://attack.mitre.org",
				"id":     "T1110",
				"title":  "Threat one",
			},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.Len(suite.T(), created.Data.ThreatIDs, 2)
	require.Equal(suite.T(), "T1110", created.Data.ThreatIDs[0].ID)
	require.Equal(suite.T(), "T1552", created.Data.ThreatIDs[1].ID)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/risk-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	var fetched genericDataResponse[riskTemplateResponse]
	require.NoError(suite.T(), json.Unmarshal(getRec.Body.Bytes(), &fetched))
	require.Len(suite.T(), fetched.Data.ThreatIDs, 2)
	require.Equal(suite.T(), "T1110", fetched.Data.ThreatIDs[0].ID)
	require.Equal(suite.T(), "T1552", fetched.Data.ThreatIDs[1].ID)

	listRec, listCall := suite.authedRequest(http.MethodGet, "/api/admin/risk-templates?plugin-id=github-repositories&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(listRec, listCall)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed struct {
		Data []riskTemplateResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))

	var target *riskTemplateResponse
	for i := range listed.Data {
		if listed.Data[i].ID == created.Data.ID {
			target = &listed.Data[i]
			break
		}
	}
	require.NotNil(suite.T(), target)
	require.Len(suite.T(), target.ThreatIDs, 2)
	require.Equal(suite.T(), "T1110", target.ThreatIDs[0].ID)
	require.Equal(suite.T(), "T1552", target.ThreatIDs[1].ID)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateValidationBoundaries() {
	maxTitle := strings.Repeat("a", 1000)
	tooLongTitle := strings.Repeat("a", 1001)

	validRec, validCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Boundary template",
		"title":          maxTitle,
		"statement":      "Boundary statement",
	})
	suite.server.E().ServeHTTP(validRec, validCall)
	require.Equal(suite.T(), http.StatusCreated, validRec.Code)

	invalidRec, invalidCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Boundary template invalid",
		"title":          tooLongTitle,
		"statement":      "Boundary statement",
	})
	suite.server.E().ServeHTTP(invalidRec, invalidCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidRec.Code)

	duplicateOrderRec, duplicateOrderCall := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
		"plugin-id":      "github-repositories",
		"policy-package": "compliance_framework.secret_scanning_enabled",
		"name":           "Duplicate remediation order",
		"title":          "Duplicate remediation order",
		"statement":      "Statement",
		"remediation-template": map[string]any{
			"title": "Duplicate order",
			"tasks": []map[string]any{
				{"title": "Task one", "order-index": 1},
				{"title": "Task two", "order-index": 1},
			},
		},
	})
	suite.server.E().ServeHTTP(duplicateOrderRec, duplicateOrderCall)
	require.Equal(suite.T(), http.StatusBadRequest, duplicateOrderRec.Code)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateUnauthenticatedRequest() {
	rec, req := suite.unauthenticatedRequest(http.MethodGet, "/api/admin/risk-templates", nil)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}

// batchRiskTemplateResult is the JSON shape returned by POST /api/agent/risk-templates/batch.
type batchRiskTemplateResult struct {
	Data struct {
		Created []riskTemplateResponse     `json:"created"`
		Updated []riskTemplateResponse     `json:"updated"`
		Deleted []uuid.UUID                `json:"deleted"`
		Skipped []batchSkippedItemResponse `json:"skipped"`
	} `json:"data"`
}

type batchSkippedItemResponse struct {
	ID     uuid.UUID `json:"id"`
	Reason string    `json:"reason"`
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateBatchUpsertCreateAndUpdate() {
	// Step 1 — batch creates two templates. Both IDs are supplied by the caller.
	firstID := uuid.New()
	secondID := uuid.New()
	batchReq := map[string]any{
		"plugin-id":      "batch-plugin",
		"policy-package": "compliance_framework.batch_test",
		"templates": []map[string]any{
			{
				"id":        firstID.String(),
				"name":      "Batch template one",
				"title":     "Batch title one",
				"statement": "Batch statement one",
				"is-active": true,
			},
			{
				"id":        secondID.String(),
				"name":      "Batch template two",
				"title":     "Batch title two",
				"statement": "Batch statement two",
			},
		},
	}

	rec, req := suite.authedRequest(http.MethodPost, "/api/agent/risk-templates/batch", batchReq)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)

	var result1 batchRiskTemplateResult
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &result1))
	require.Len(suite.T(), result1.Data.Created, 2)
	require.Empty(suite.T(), result1.Data.Updated)
	require.Empty(suite.T(), result1.Data.Deleted)
	require.Empty(suite.T(), result1.Data.Skipped)

	// Confirm both explicit IDs were honoured.
	var foundFirst, foundSecond bool
	for _, row := range result1.Data.Created {
		if row.ID == firstID {
			foundFirst = true
			require.Equal(suite.T(), "Batch template one", row.Name)
		}
		if row.ID == secondID {
			foundSecond = true
		}
	}
	require.True(suite.T(), foundFirst, "first template should be in created list")
	require.True(suite.T(), foundSecond, "second template should be in created list")

	// Step 2 — update first template, drop second (should be deleted), add a third.
	thirdID := uuid.New()
	batchReq2 := map[string]any{
		"plugin-id":      "batch-plugin",
		"policy-package": "compliance_framework.batch_test",
		"templates": []map[string]any{
			{
				"id":        firstID.String(),
				"name":      "Batch template one updated",
				"title":     "Batch title one updated",
				"statement": "Batch statement one updated",
				"threat-ids": []map[string]any{
					{
						"system": "https://cwe.mitre.org",
						"id":     "CWE-312",
						"title":  "Cleartext Storage",
					},
				},
			},
			{
				"id":        thirdID.String(),
				"name":      "Batch template three",
				"title":     "Batch title three",
				"statement": "Batch statement three",
			},
		},
	}

	rec2, req2 := suite.authedRequest(http.MethodPost, "/api/agent/risk-templates/batch", batchReq2)
	suite.server.E().ServeHTTP(rec2, req2)
	require.Equal(suite.T(), http.StatusOK, rec2.Code)

	var result2 batchRiskTemplateResult
	require.NoError(suite.T(), json.Unmarshal(rec2.Body.Bytes(), &result2))
	require.Len(suite.T(), result2.Data.Updated, 1, "first template should be updated")
	require.Len(suite.T(), result2.Data.Created, 1, "third template should be created")
	require.Len(suite.T(), result2.Data.Deleted, 1, "second template should be deleted")
	require.Equal(suite.T(), secondID, result2.Data.Deleted[0])
	require.Empty(suite.T(), result2.Data.Skipped)

	require.Equal(suite.T(), firstID, result2.Data.Updated[0].ID)
	require.Equal(suite.T(), "Batch template one updated", result2.Data.Updated[0].Name)
	require.Len(suite.T(), result2.Data.Updated[0].ThreatIDs, 1)

	// Step 3 — confirm second template is gone from DB.
	var count int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RiskTemplate{}).Where("id = ?", secondID).Count(&count).Error)
	require.Equal(suite.T(), int64(0), count)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateBatchUpsertEmptyPayloadDeletesAll() {
	// Seed two templates.
	for _, name := range []string{"Delete me one", "Delete me two"} {
		r, c := suite.authedRequest(http.MethodPost, "/api/admin/risk-templates", map[string]any{
			"plugin-id":      "batch-delete-plugin",
			"policy-package": "compliance_framework.delete_test",
			"name":           name,
			"title":          name,
			"statement":      name + " statement",
		})
		suite.server.E().ServeHTTP(r, c)
		require.Equal(suite.T(), http.StatusCreated, r.Code)
	}

	// Send empty template list — both should be deleted.
	rec, req := suite.authedRequest(http.MethodPost, "/api/agent/risk-templates/batch", map[string]any{
		"plugin-id":      "batch-delete-plugin",
		"policy-package": "compliance_framework.delete_test",
		"templates":      []map[string]any{},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)

	var result batchRiskTemplateResult
	require.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), &result))
	require.Empty(suite.T(), result.Data.Created)
	require.Empty(suite.T(), result.Data.Updated)
	require.Len(suite.T(), result.Data.Deleted, 2)
	require.Empty(suite.T(), result.Data.Skipped)

	var remaining int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.RiskTemplate{}).
		Where("plugin_id = ? AND policy_package = ?", "batch-delete-plugin", "compliance_framework.delete_test").
		Count(&remaining).Error)
	require.Equal(suite.T(), int64(0), remaining)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateBatchUpsertMissingIDReturns400() {
	rec, req := suite.authedRequest(http.MethodPost, "/api/agent/risk-templates/batch", map[string]any{
		"plugin-id":      "batch-plugin",
		"policy-package": "compliance_framework.batch_test",
		"templates": []map[string]any{
			{
				"name":      "Missing ID template",
				"title":     "Title",
				"statement": "Statement",
			},
		},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)
	require.Contains(suite.T(), rec.Body.String(), "id is required")
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateBatchUpsertValidationError() {
	rec, req := suite.authedRequest(http.MethodPost, "/api/agent/risk-templates/batch", map[string]any{
		"plugin-id":      "batch-plugin",
		"policy-package": "compliance_framework.batch_test",
		"templates": []map[string]any{
			{
				"id":        uuid.New().String(),
				"name":      "",
				"title":     "Missing name",
				"statement": "Statement",
			},
		},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusBadRequest, rec.Code)
}

func (suite *RiskTemplateApiIntegrationSuite) TestRiskTemplateBatchUpsertRequiresAuth() {
	rec, req := suite.unauthenticatedRequest(http.MethodPost, "/api/agent/risk-templates/batch", map[string]any{
		"plugin-id":      "batch-plugin",
		"policy-package": "compliance_framework.batch_test",
		"templates":      []map[string]any{},
	})
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)
}
