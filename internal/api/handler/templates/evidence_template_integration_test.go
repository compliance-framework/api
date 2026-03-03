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

type EvidenceTemplateApiIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

type evidenceTemplateSelectorLabelAPIResponse struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type evidenceTemplateLabelSchemaFieldAPIResponse struct {
	Key      string `json:"key"`
	Required bool   `json:"required"`
}

type evidenceTemplateAPIResponse struct {
	ID                 uuid.UUID                                     `json:"id"`
	CreatedAt          time.Time                                     `json:"createdAt"`
	UpdatedAt          time.Time                                     `json:"updatedAt"`
	PluginID           string                                        `json:"pluginId"`
	PolicyPackage      string                                        `json:"policyPackage"`
	Title              string                                        `json:"title"`
	Description        string                                        `json:"description"`
	Methods            []string                                      `json:"methods"`
	IsActive           bool                                          `json:"isActive"`
	SelectorLabels     []evidenceTemplateSelectorLabelAPIResponse    `json:"selectorLabels"`
	LabelSchema        []evidenceTemplateLabelSchemaFieldAPIResponse `json:"labelSchema"`
	RiskTemplateIDs    []uuid.UUID                                   `json:"riskTemplateIds"`
	SubjectTemplateIDs []uuid.UUID                                   `json:"subjectTemplateIds"`
}

type evidenceTemplateDataEnvelope struct {
	Data evidenceTemplateAPIResponse `json:"data"`
}

func TestEvidenceTemplateAPI(t *testing.T) {
	suite.Run(t, new(EvidenceTemplateApiIntegrationSuite))
}

func (suite *EvidenceTemplateApiIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &handlerpkg.APIServices{}
	handlerpkg.RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, services)
}

func (suite *EvidenceTemplateApiIntegrationSuite) authedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

func (suite *EvidenceTemplateApiIntegrationSuite) unauthenticatedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateCRUD() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Secret scanning status evidence",
		"description":   "Captures secret scanning enablement status.",
		"methods":       []string{"TEST"},
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
			{"key": "plugin.id", "value": "github-repositories"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org", "description": "GitHub organization login", "required": true},
			{"key": "github.repo", "description": "GitHub repository full name", "required": true},
		},
		"isActive": true,
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEqual(suite.T(), uuid.Nil, created.Data.ID)
	require.False(suite.T(), created.Data.CreatedAt.IsZero())
	require.False(suite.T(), created.Data.UpdatedAt.IsZero())
	require.Equal(suite.T(), "github-repositories", created.Data.PluginID)
	require.Equal(suite.T(), "compliance_framework.secret_scanning_enabled", created.Data.PolicyPackage)
	require.Equal(suite.T(), "Secret scanning status evidence", created.Data.Title)
	require.True(suite.T(), created.Data.IsActive)
	require.Len(suite.T(), created.Data.Methods, 1)
	require.Equal(suite.T(), "TEST", created.Data.Methods[0])
	require.Len(suite.T(), created.Data.SelectorLabels, 2)
	require.Len(suite.T(), created.Data.LabelSchema, 2)
	require.Empty(suite.T(), created.Data.RiskTemplateIDs)
	require.Empty(suite.T(), created.Data.SubjectTemplateIDs)

	listRec, listCall := suite.authedRequest(http.MethodGet, "/api/evidence-templates?pluginId=github-repositories&isActive=true&page=1&limit=10", nil)
	suite.server.E().ServeHTTP(listRec, listCall)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed struct {
		Data []evidenceTemplateAPIResponse `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.NotEmpty(suite.T(), listed.Data)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/evidence-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/evidence-templates/%s", created.Data.ID), map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Secret scanning status evidence updated",
		"description":   "Updated description.",
		"methods":       []string{"TEST", "EXAMINE"},
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org", "description": "GitHub organization login", "required": true},
		},
		"isActive": false,
	})
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.Equal(suite.T(), "Secret scanning status evidence updated", updated.Data.Title)
	require.False(suite.T(), updated.Data.IsActive)
	require.Len(suite.T(), updated.Data.Methods, 2)
	require.Len(suite.T(), updated.Data.SelectorLabels, 1)
	require.Len(suite.T(), updated.Data.LabelSchema, 1)

	var selectorCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.EvidenceTemplateSelectorLabel{}).Where("evidence_template_id = ?", created.Data.ID).Count(&selectorCount).Error)
	require.Equal(suite.T(), int64(1), selectorCount)

	var schemaCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.EvidenceTemplateLabelSchemaField{}).Where("evidence_template_id = ?", created.Data.ID).Count(&schemaCount).Error)
	require.Equal(suite.T(), int64(1), schemaCount)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateWithLinkedTemplates() {
	riskCreateRec, riskCreateCall := suite.authedRequest(http.MethodPost, "/api/risk-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"name":          "Secret scanning risk",
		"title":         "Undetected secrets",
		"statement":     "Secret scanning is disabled.",
	})
	suite.server.E().ServeHTTP(riskCreateRec, riskCreateCall)
	require.Equal(suite.T(), http.StatusCreated, riskCreateRec.Code)

	var riskCreated struct {
		Data struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(riskCreateRec.Body.Bytes(), &riskCreated))

	subjectCreateRec, subjectCreateCall := suite.authedRequest(http.MethodPost, "/api/subject-templates", map[string]any{
		"name":              "GitHub repository subject",
		"type":              "inventory-item",
		"identityLabelKeys": []string{"github.repo"},
		"sourceMode":        "runtime-derived",
		"selectorLabels": []map[string]any{
			{"key": "plugin.id", "value": "github-repositories"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.repo", "description": "GitHub repository full name"},
		},
	})
	suite.server.E().ServeHTTP(subjectCreateRec, subjectCreateCall)
	require.Equal(suite.T(), http.StatusCreated, subjectCreateRec.Code)

	var subjectCreated struct {
		Data struct {
			ID uuid.UUID `json:"id"`
		} `json:"data"`
	}
	require.NoError(suite.T(), json.Unmarshal(subjectCreateRec.Body.Bytes(), &subjectCreated))

	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Secret scanning evidence with links",
		"methods":       []string{"TEST"},
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.repo"},
		},
		"riskTemplateIds":    []string{riskCreated.Data.ID.String()},
		"subjectTemplateIds": []string{subjectCreated.Data.ID.String()},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.Len(suite.T(), created.Data.RiskTemplateIDs, 1)
	require.Equal(suite.T(), riskCreated.Data.ID, created.Data.RiskTemplateIDs[0])
	require.Len(suite.T(), created.Data.SubjectTemplateIDs, 1)
	require.Equal(suite.T(), subjectCreated.Data.ID, created.Data.SubjectTemplateIDs[0])

	var riskLinkCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.EvidenceTemplateRiskTemplate{}).Where("evidence_template_id = ?", created.Data.ID).Count(&riskLinkCount).Error)
	require.Equal(suite.T(), int64(1), riskLinkCount)

	updateRec, updateCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/evidence-templates/%s", created.Data.ID), map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Secret scanning evidence with links updated",
		"methods":       []string{"TEST"},
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.repo"},
		},
	})
	suite.server.E().ServeHTTP(updateRec, updateCall)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updatedLinks evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updatedLinks))
	require.Empty(suite.T(), updatedLinks.Data.RiskTemplateIDs)
	require.Empty(suite.T(), updatedLinks.Data.SubjectTemplateIDs)

	var riskLinkCountAfterUpdate int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.EvidenceTemplateRiskTemplate{}).Where("evidence_template_id = ?", created.Data.ID).Count(&riskLinkCountAfterUpdate).Error)
	require.Equal(suite.T(), int64(0), riskLinkCountAfterUpdate)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateLinkedIDValidation() {
	nonExistentID := uuid.New()

	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Template with missing risk link",
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.repo"},
		},
		"riskTemplateIds": []string{nonExistentID.String()},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusBadRequest, createRec.Code)
	require.Contains(suite.T(), createRec.Body.String(), "riskTemplateIds were not found")
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateEmptySelectorLabelsRejected() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":       "github-repositories",
		"policyPackage":  "compliance_framework.secret_scanning_enabled",
		"title":          "Template without selectors",
		"selectorLabels": []map[string]any{},
		"labelSchema": []map[string]any{
			{"key": "github.org"},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusBadRequest, createRec.Code)
	require.Contains(suite.T(), createRec.Body.String(), "selectorLabels is required")
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateDeleteCleansDependentRows() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Template for delete",
		"methods":       []string{"TEST"},
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org", "required": true},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))

	deleteRec, deleteCall := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/evidence-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteCall)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)

	getRec, getCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/evidence-templates/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getCall)
	require.Equal(suite.T(), http.StatusNotFound, getRec.Code)

	var selectorCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.EvidenceTemplateSelectorLabel{}).Where("evidence_template_id = ?", created.Data.ID).Count(&selectorCount).Error)
	require.Equal(suite.T(), int64(0), selectorCount)

	var schemaCount int64
	require.NoError(suite.T(), suite.DB.Model(&templaterel.EvidenceTemplateLabelSchemaField{}).Where("evidence_template_id = ?", created.Data.ID).Count(&schemaCount).Error)
	require.Equal(suite.T(), int64(0), schemaCount)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateValidationAndNotFound() {
	badCreateRec, badCreateCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId": "",
	})
	suite.server.E().ServeHTTP(badCreateRec, badCreateCall)
	require.Equal(suite.T(), http.StatusBadRequest, badCreateRec.Code)

	invalidIDRec, invalidIDCall := suite.authedRequest(http.MethodGet, "/api/evidence-templates/not-a-uuid", nil)
	suite.server.E().ServeHTTP(invalidIDRec, invalidIDCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidIDRec.Code)

	missingIDRec, missingIDCall := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/evidence-templates/%s", uuid.New()), nil)
	suite.server.E().ServeHTTP(missingIDRec, missingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, missingIDRec.Code)

	putMissingIDRec, putMissingIDCall := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/evidence-templates/%s", uuid.New()), map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Missing template",
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org"},
		},
	})
	suite.server.E().ServeHTTP(putMissingIDRec, putMissingIDCall)
	require.Equal(suite.T(), http.StatusNotFound, putMissingIDRec.Code)

	invalidFilterRec, invalidFilterCall := suite.authedRequest(http.MethodGet, "/api/evidence-templates?isActive=definitely-not-bool", nil)
	suite.server.E().ServeHTTP(invalidFilterRec, invalidFilterCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidFilterRec.Code)
	require.Contains(suite.T(), invalidFilterRec.Body.String(), "definitely-not-bool")

	invalidMethodRec, invalidMethodCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Invalid method template",
		"methods":       []string{"INVALID"},
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org"},
		},
	})
	suite.server.E().ServeHTTP(invalidMethodRec, invalidMethodCall)
	require.Equal(suite.T(), http.StatusBadRequest, invalidMethodRec.Code)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateDefaultIsActive() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Active by default template",
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.secret_scanning_enabled"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org"},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.True(suite.T(), created.Data.IsActive)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateSelectorLabelsOrderedAsc() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.secret_scanning_enabled",
		"title":         "Ordered selector labels template",
		"selectorLabels": []map[string]any{
			{"key": "z_label", "value": "z"},
			{"key": "a_label", "value": "a"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org"},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created evidenceTemplateDataEnvelope
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.Len(suite.T(), created.Data.SelectorLabels, 2)
	require.Equal(suite.T(), "a_label", created.Data.SelectorLabels[0].Key)
	require.Equal(suite.T(), "z_label", created.Data.SelectorLabels[1].Key)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateRequiresAuthentication() {
	rec, req := suite.unauthenticatedRequest(http.MethodGet, "/api/evidence-templates", nil)
	suite.server.E().ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}

func (suite *EvidenceTemplateApiIntegrationSuite) TestEvidenceTemplateFilterByPolicyPackage() {
	createRec, createCall := suite.authedRequest(http.MethodPost, "/api/evidence-templates", map[string]any{
		"pluginId":      "github-repositories",
		"policyPackage": "compliance_framework.unique_policy",
		"title":         "Unique policy template",
		"selectorLabels": []map[string]any{
			{"key": "_policy", "value": "compliance_framework.unique_policy"},
		},
		"labelSchema": []map[string]any{
			{"key": "github.org"},
		},
	})
	suite.server.E().ServeHTTP(createRec, createCall)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	listRec, listCall := suite.authedRequest(http.MethodGet, "/api/evidence-templates?policyPackage=compliance_framework.unique_policy", nil)
	suite.server.E().ServeHTTP(listRec, listCall)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed struct {
		Data  []evidenceTemplateAPIResponse `json:"data"`
		Total int64                         `json:"total"`
	}
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.Equal(suite.T(), int64(1), listed.Total)
	require.Len(suite.T(), listed.Data, 1)
	require.Equal(suite.T(), "compliance_framework.unique_policy", listed.Data[0].PolicyPackage)
}
