//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal"
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	svc "github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"

	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestEvidenceApi(t *testing.T) {
	suite.Run(t, new(EvidenceApiIntegrationSuite))
}

type EvidenceApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *EvidenceApiIntegrationSuite) setupServer() *api.Server {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	services.EvidenceService = evidenceSvc
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
	return server
}

func (suite *EvidenceApiIntegrationSuite) TestCreate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	// Create two catalogs with the same group ID structure
	evidence := EvidenceCreateRequest{
		UUID:    uuid.New(),
		Title:   "Some piece of evidence",
		Start:   time.Now().Add(-time.Hour),
		End:     time.Now().Add(-time.Hour).Add(time.Minute),
		Expires: internal.Pointer(time.Now().Add(30 * 24 * time.Hour)),
		Labels: map[string]string{
			"provider": "aws",
			"service":  "EC2",
			"instance": "i-12345",
		},
		Activities: []EvidenceActivity{
			{
				UUID:  uuid.New(),
				Title: "Collect evidence",
				Steps: []EvidenceActivityStep{
					{
						UUID:  uuid.New(),
						Title: "Run CLI to collect configuration",
					},
					{
						UUID:  uuid.New(),
						Title: "Convert to JSON object",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Evaluate compliance to policies",
				Steps: []EvidenceActivityStep{
					{
						UUID:  uuid.New(),
						Title: "Pass JSON configuration into policy engine",
					},
					{
						UUID:  uuid.New(),
						Title: "Evaluate policy and generate results",
					},
				},
			},
		},
		InventoryItems: []EvidenceInventoryItem{
			{
				Identifier: "web-server/ec2/i-12345",
				Type:       "web-server",
				Title:      "EC2 Instance - i-12345",
				Props:      nil,
				Links:      nil,
				ImplementedComponents: []struct {
					Identifier string
				}{
					{
						Identifier: "components/common/ssh",
					},
					{
						Identifier: "components/common/ubuntu-22",
					},
				},
			},
		},
		Components: []EvidenceComponent{
			{
				Identifier:  "components/common/ssh",
				Type:        "software",
				Title:       "Secure Shell (SSH)",
				Description: "SSH is used to manage remote access to virtual and hardware servers.",
				Protocols: []oscalTypes_1_1_3.Protocol{
					{
						UUID:  "3480C9EC-BC6B-4851-B248-BA78D83ECECE",
						Title: "SSH",
						Name:  "SSH",
						PortRanges: &[]oscalTypes_1_1_3.PortRange{
							{
								End:       22,
								Start:     22,
								Transport: "TCP",
							},
						},
					},
				},
			},
			{
				Identifier:  "components/common/ubuntu-22.04",
				Type:        "operating-system",
				Title:       "Ubuntu Server v22.04",
				Description: "Ubuntu is a free, open-source Linux distribution maintained by Canonical that pairs a user-friendly desktop and server experience with regular, predictable releases. It comes with extensive repositories, strong security defaults, and long-term support options that make it popular for personal use, cloud deployments, and enterprise environments.",
			},
			{
				Identifier:  "components/common/aws/ec2",
				Type:        "service",
				Title:       "Amazon Elastic Compute Cloud (EC2)",
				Description: "Amazon Elastic Compute Cloud (EC2) is a web service that lets you quickly provision resizable virtual servers in AWS’s global cloud, paying only for the compute you use. It offers a choice of instance types, networking and storage options, and automation features that allow everything from burst-scale web apps to enterprise workloads to run securely and on demand.",
			},
		},
		Subjects: []EvidenceSubject{
			{
				Identifier: "web-server/ec2/i-12345",
				Type:       "inventory-item",
			},
			{
				Identifier: "components/common/ssh",
				Type:       "component",
			},
			{
				Identifier: "components/common/aws/ec2",
				Type:       "component",
			},
		},
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			Reason:  "fail", // "pass" | "fail" | "other"
			Remarks: "Policy evaluation failed as password authentication is enabled. SSH password authentication should be disabled.",
			State:   "not-satisfied", // "satisfied" | "not-satisfied"
		},
	}

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(evidence)
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var count int64
	// Counting users with specific names
	suite.DB.Model(&relational.Evidence{}).Count(&count)
	suite.Equal(int64(1), count)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateRequiresAgentAuthWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateWithAgentTokenWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	agent, err := suite.CreateAgent("evidence-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "evidence-key")
	suite.Require().NoError(err)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Require().NotNil(evidence.Signature)
	suite.Equal(relational.AgentAuthMethodServiceAccount, evidence.Signature.Data().Claims.AuthMethod)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateRejectsExpiredAgentKeyWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	agent, err := suite.CreateAgent("expired-evidence-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "expired-evidence-key")
	suite.Require().NoError(err)
	expiresAt := time.Now().UTC().Add(-time.Minute)
	key.ExpiresAt = &expiresAt
	suite.Require().NoError(suite.DB.Save(key).Error)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusForbidden, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestCreateWithUserTokenSignsEvidenceAndReturnsSignature() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Require().NotNil(evidence.Signature)
	suite.Equal("dummy@example.com", evidence.Signature.Data().Claims.Subject)

	var response map[string]any
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	data, ok := response["data"].(map[string]any)
	suite.Require().True(ok)
	suite.NotNil(data["signature"])
}

func (suite *EvidenceApiIntegrationSuite) TestCreatePublicLeavesEvidenceUnsigned() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Unsigned Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Nil(evidence.Signature)
}

func (suite *EvidenceApiIntegrationSuite) TestCreatePublicIgnoresInvalidUserCookie() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Unsigned Evidence With Invalid Cookie",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.AddCookie(&http.Cookie{
		Name:  "ccf_auth_token",
		Value: "invalid-token",
	})
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Nil(evidence.Signature)
}

func (suite *EvidenceApiIntegrationSuite) TestSignatureEndpointsRequireUserAuth() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String()+"/signature", nil)
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusUnauthorized, signatureRec.Code)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusUnauthorized, verifyRec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSignatureEndpointsWithUserAuth() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
		Props: []oscalTypes_1_1_3.Property{{Name: "check", Value: "baseline"}},
		Labels: map[string]string{
			"env": "prod",
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String()+"/signature", nil)
	signatureReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusOK, signatureRec.Code)

	var signatureResp EvidenceSignatureResponse
	suite.Require().NoError(json.Unmarshal(signatureRec.Body.Bytes(), &signatureResp))
	suite.Require().NotNil(signatureResp.Data)
	suite.Equal(evidencesvc.SignatureStatusSigned, signatureResp.Data.Status)
	suite.Require().NotNil(signatureResp.Data.Signature)
	suite.NotEmpty(signatureResp.Data.Signature.JWS)
	suite.Equal("dummy@example.com", signatureResp.Data.Signature.Claims.Subject)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	var verifyResp EvidenceSignatureVerificationResponse
	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.Equal(evidencesvc.SignatureStatusSigned, verifyResp.Data.Status)
	suite.Require().NotNil(verifyResp.Data.Signature)
	suite.True(verifyResp.Data.IsValid)

	suite.Require().NoError(
		suite.DB.Model(&relational.Evidence{}).
			Where("id = ?", evidence.ID).
			Update("status", datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusNotSatisfied})).Error,
	)

	verifyReq = httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	verifyRec = httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.False(verifyResp.Data.IsValid)
	suite.False(verifyResp.Data.Checks.HashMatch)
	suite.False(verifyResp.Data.Checks.SignedContentMatches)
}

func (suite *EvidenceApiIntegrationSuite) TestPublicEvidenceReadsDoNotExposeSignature() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Signed Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)
	suite.Require().NotNil(evidence.Signature)

	getReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String(), nil)
	getRec := httptest.NewRecorder()
	server.E().ServeHTTP(getRec, getReq)
	suite.Equal(http.StatusOK, getRec.Code)

	var getResp map[string]any
	suite.Require().NoError(json.Unmarshal(getRec.Body.Bytes(), &getResp))
	getData, ok := getResp["data"].(map[string]any)
	suite.Require().True(ok)
	suite.NotContains(getData, "signature")

	historyReq := httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+evidence.UUID.String(), nil)
	historyRec := httptest.NewRecorder()
	server.E().ServeHTTP(historyRec, historyReq)
	suite.Equal(http.StatusOK, historyRec.Code)

	var historyResp map[string]any
	suite.Require().NoError(json.Unmarshal(historyRec.Body.Bytes(), &historyResp))
	historyData, ok := historyResp["data"].([]any)
	suite.Require().True(ok)
	suite.Require().Len(historyData, 1)
	firstItem, ok := historyData[0].(map[string]any)
	suite.Require().True(ok)
	suite.NotContains(firstItem, "signature")
}

func (suite *EvidenceApiIntegrationSuite) TestVerifyUnsignedEvidenceReturnsFailureResult() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	server := suite.setupServer()
	userToken, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Unsigned Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *userToken))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	var verifyResp EvidenceSignatureVerificationResponse
	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.Equal(evidencesvc.SignatureStatusUnsigned, verifyResp.Data.Status)
	suite.Nil(verifyResp.Data.Signature)
	suite.False(verifyResp.Data.IsValid)
	suite.Empty(verifyResp.Data.Errors)

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+evidence.ID.String()+"/signature", nil)
	signatureReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *userToken))
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusOK, signatureRec.Code)

	var signatureResp EvidenceSignatureResponse
	suite.Require().NoError(json.Unmarshal(signatureRec.Body.Bytes(), &signatureResp))
	suite.Require().NotNil(signatureResp.Data)
	suite.Equal(evidencesvc.SignatureStatusUnsigned, signatureResp.Data.Status)
	suite.Nil(signatureResp.Data.Signature)
}

func (suite *EvidenceApiIntegrationSuite) TestVerifyAgentCreatedEvidenceWithUserAuth() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	userToken, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	agent, err := suite.CreateAgent("verify-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "verify-key")
	suite.Require().NoError(err)
	agentToken, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)

	createRec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(EvidenceCreateRequest{
		UUID:  uuid.New(),
		Title: "Agent Evidence",
		Start: time.Now().Add(-time.Hour),
		End:   time.Now().Add(-time.Minute),
		Status: oscalTypes_1_1_3.ObjectiveStatus{
			State: relational.EvidenceStatusSatisfied,
		},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/api/evidence", bytes.NewReader(reqBody))
	createReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	createReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *agentToken))
	server.E().ServeHTTP(createRec, createReq)
	suite.Equal(http.StatusCreated, createRec.Code)

	var evidence relational.Evidence
	suite.Require().NoError(suite.DB.First(&evidence).Error)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+evidence.ID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *userToken))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusOK, verifyRec.Code)

	var verifyResp EvidenceSignatureVerificationResponse
	suite.Require().NoError(json.Unmarshal(verifyRec.Body.Bytes(), &verifyResp))
	suite.Require().NotNil(verifyResp.Data)
	suite.Equal(evidencesvc.SignatureStatusSigned, verifyResp.Data.Status)
	suite.Require().NotNil(verifyResp.Data.Signature)
	suite.True(verifyResp.Data.IsValid)
	suite.Equal(authn.TokenKindAgent, verifyResp.Data.Signer.Type)
}

func (suite *EvidenceApiIntegrationSuite) TestSignatureEndpointsReturnNotFoundForMissingEvidence() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	missingID := uuid.New()

	signatureReq := httptest.NewRequest(http.MethodGet, "/api/evidence/"+missingID.String()+"/signature", nil)
	signatureReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	signatureRec := httptest.NewRecorder()
	server.E().ServeHTTP(signatureRec, signatureReq)
	suite.Equal(http.StatusNotFound, signatureRec.Code)

	verifyReq := httptest.NewRequest(http.MethodPost, "/api/evidence/"+missingID.String()+"/verify", nil)
	verifyReq.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	verifyRec := httptest.NewRecorder()
	server.E().ServeHTTP(verifyRec, verifyReq)
	suite.Equal(http.StatusNotFound, verifyRec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSearch() {
	suite.Run("Returns the single latest evidence for a stream", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		stream := uuid.New()

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  stream,
				Title: "New",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  stream,
				Title: "Old",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(struct {
			Filter labelfilter.Filter
		}{})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
	})

	suite.Run("Returns the single latest evidence for two streams", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "New",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Old",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(struct {
			Filter labelfilter.Filter
		}{})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 2)
	})

	suite.Run("Can filter streams - simple", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "New",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Old",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "Github",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		var reqBody, _ = json.Marshal(struct {
			Filter labelfilter.Filter
		}{
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal(response.Data[0].Title, "New")
	})

	suite.Run("Can filter streams - negation", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "AWS",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "Github",
				Start: time.Now().Add(-2 * time.Hour),
				End:   time.Now().Add(-2 * time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "Github",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		var reqBody, _ = json.Marshal(struct {
			Filter labelfilter.Filter
		}{
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "!=",
						Value:    "aws",
					},
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal("Github", response.Data[0].Title)
	})

	suite.Run("Can filter streams - complex subquery", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create two catalogs with the same group ID structure
		evidence := []relational.Evidence{
			{
				UUID:  uuid.New(),
				Title: "AWS-1",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
					{
						Name:  "instance",
						Value: "i-1",
					},
				},
			},
			{
				UUID:  uuid.New(),
				Title: "AWS-2",
				Start: time.Now().Add(-time.Hour),
				End:   time.Now().Add(-time.Hour).Add(time.Minute),
				Labels: []relational.Labels{
					{
						Name:  "provider",
						Value: "AWS",
					},
					{
						Name:  "instance",
						Value: "i-2",
					},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		var reqBody, _ = json.Marshal(struct {
			Filter labelfilter.Filter
		}{
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Query: &labelfilter.Query{
						Operator: "and",
						Scopes: []labelfilter.Scope{
							{
								Condition: &labelfilter.Condition{
									Label:    "provider",
									Operator: "=",
									Value:    "aws",
								},
							},
							{
								Query: &labelfilter.Query{
									Operator: "or",
									Scopes: []labelfilter.Scope{
										{
											Condition: &labelfilter.Condition{
												Label:    "instance",
												Operator: "=",
												Value:    "i-1",
											},
										},
										{
											Condition: &labelfilter.Condition{
												Label:    "instance",
												Operator: "=",
												Value:    "i-3",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/evidence/search", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := &svc.ListResponse[PublicEvidenceResponse]{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		suite.Len(response.Data, 1)
		suite.Equal(response.Data[0].Title, "AWS-1")
	})
}

func (suite *EvidenceApiIntegrationSuite) TestHistoryPagination() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	streamUUID := uuid.New()
	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  streamUUID,
			Title: "Newest",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "Middle",
			Start: now.Add(-12 * time.Minute),
			End:   now.Add(-10 * time.Minute),
		},
		{
			UUID:  streamUUID,
			Title: "Oldest",
			Start: now.Add(-22 * time.Minute),
			End:   now.Add(-20 * time.Minute),
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+streamUUID.String()+"?page=1&limit=2", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var response struct {
		Data       []PublicEvidenceResponse `json:"data"`
		Total      int64                    `json:"total"`
		Page       int                      `json:"page"`
		Limit      int                      `json:"limit"`
		TotalPages int                      `json:"totalPages"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 2)
	suite.Equal(int64(3), response.Total)
	suite.Equal(1, response.Page)
	suite.Equal(2, response.Limit)
	suite.Equal(2, response.TotalPages)
	suite.Equal("Newest", response.Data[0].Title)
	suite.Equal("Middle", response.Data[1].Title)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+streamUUID.String()+"?page=2&limit=2", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 1)
	suite.Equal(2, response.Page)
	suite.Equal("Oldest", response.Data[0].Title)
}

func (suite *EvidenceApiIntegrationSuite) TestHistoryPaginationRejectsInvalidParams() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+uuid.New().String()+"?page=0&limit=10", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/evidence/history/"+uuid.New().String()+"?page=1&limit=0", nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchPagination() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  uuid.New(),
			Title: "Newest",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "Middle",
			Start: now.Add(-12 * time.Minute),
			End:   now.Add(-10 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "Oldest",
			Start: now.Add(-22 * time.Minute),
			End:   now.Add(-20 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()

	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{
		Filter: labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "provider",
					Operator: "=",
					Value:    "aws",
				},
			},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=1&limit=2", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var response svc.ListResponse[PublicEvidenceResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 2)
	suite.Equal(int64(3), response.Total)
	suite.Equal(1, response.Page)
	suite.Equal(2, response.Limit)
	suite.Equal(2, response.TotalPages)
	suite.Equal("Newest", response.Data[0].Title)
	suite.Equal("Middle", response.Data[1].Title)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=2&limit=2", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Len(response.Data, 1)
	suite.Equal(2, response.Page)
	suite.Equal("Oldest", response.Data[0].Title)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchPaginationRejectsInvalidParams() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=0&limit=10", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/search?page=1&limit=0", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchSortingAndNameFiltering() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now().UTC()
	stream := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	evidences := []relational.Evidence{
		{
			UUID:  stream,
			Title: "Zeta Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			Title: "Alpha Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "not-satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.MustParse("00000000-0000-0000-0000-000000000002"),
			Title: "Beta Evidence",
			Start: now.Add(-4 * time.Minute),
			End:   now.Add(-3 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "GCP"},
			},
		},
		{
			UUID:  stream,
			Title: "Old Zeta Evidence",
			Start: now.Add(-11 * time.Minute),
			End:   now.Add(-10 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{
				State: "not-satisfied",
			}),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})

	search := func(path string) svc.ListResponse[PublicEvidenceResponse] {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusOK, rec.Code)

		var response svc.ListResponse[PublicEvidenceResponse]
		suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
		return response
	}

	response := search("/api/evidence/search")
	suite.Equal(int64(3), response.Total)
	suite.Equal([]string{"Zeta Evidence", "Alpha Evidence", "Beta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?sortBy=lastSeenAt&sortDirection=asc")
	suite.Equal([]string{"Beta Evidence", "Alpha Evidence", "Zeta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?sortBy=name&sortDirection=asc")
	suite.Equal([]string{"Alpha Evidence", "Beta Evidence", "Zeta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?sortBy=status&sortDirection=asc")
	suite.Equal([]string{"Alpha Evidence", "Beta Evidence", "Zeta Evidence"}, evidenceTitles(response.Data))

	response = search("/api/evidence/search?name=alpha")
	suite.Equal(int64(1), response.Total)
	suite.Equal([]string{"Alpha Evidence"}, evidenceTitles(response.Data))
}

func (suite *EvidenceApiIntegrationSuite) TestSearchCombinesLabelAndNameFilters() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	now := time.Now().UTC()
	evidences := []relational.Evidence{
		{
			UUID:  uuid.New(),
			Title: "AWS Evidence",
			Start: now.Add(-2 * time.Minute),
			End:   now.Add(-1 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "AWS"},
			},
		},
		{
			UUID:  uuid.New(),
			Title: "AWS Evidence",
			Start: now.Add(-3 * time.Minute),
			End:   now.Add(-2 * time.Minute),
			Labels: []relational.Labels{
				{Name: "provider", Value: "GCP"},
			},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidences).Error)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{
		Filter: labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "provider",
					Operator: "=",
					Value:    "aws",
				},
			},
		},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?name=aws", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)

	var response svc.ListResponse[PublicEvidenceResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(int64(1), response.Total)
	suite.Equal([]string{"AWS Evidence"}, evidenceTitles(response.Data))
	suite.Equal("AWS", response.Data[0].Labels[0].Value)
}

func (suite *EvidenceApiIntegrationSuite) TestSearchRejectsInvalidSortParams() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	server := suite.setupServer()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/search?sortBy=createdAt", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/evidence/search?sortDirection=sideways", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusBadRequest, rec.Code)
}

func evidenceTitles(items []PublicEvidenceResponse) []string {
	titles := make([]string, 0, len(items))
	for _, item := range items {
		titles = append(titles, item.Title)
	}
	return titles
}

func (suite *EvidenceApiIntegrationSuite) TestStatusOverTime() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	stream := uuid.New()

	now := time.Now()
	evidence := []relational.Evidence{
		{
			UUID:   stream,
			Title:  "E1",
			Start:  now.Add(-2 * time.Minute),
			End:    now.Add(-1 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		},
		{
			UUID:   stream,
			Title:  "E2",
			Start:  now.Add(-12 * time.Minute),
			End:    now.Add(-10 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		},
		{
			UUID:   stream,
			Title:  "E3",
			Start:  now.Add(-22 * time.Minute),
			End:    now.Add(-20 * time.Minute),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		},
		{
			UUID:   stream,
			Title:  "E4",
			Start:  now.Add(-6 * time.Hour),
			End:    now.Add(-5 * time.Hour),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
		},
	}
	suite.NoError(suite.DB.Create(&evidence).Error)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
	services.EvidenceService = evidenceSvc
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(struct {
		Filter labelfilter.Filter
	}{})
	req := httptest.NewRequest(http.MethodPost, "/api/evidence/status-over-time", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	response := struct {
		Data []struct {
			Interval time.Time
			Statuses []struct {
				Count  int64
				Status string
			}
		} `json:"data"`
	}{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err)

	suite.Len(response.Data, 7)
	suite.NotContains(rec.Body.String(), `"statuses":null`)

	// verify counts for each interval
	toMap := func(in []struct {
		Count  int64
		Status string
	}) map[string]int64 {
		m := make(map[string]int64)
		for _, s := range in {
			m[s.Status] = s.Count
		}
		return m
	}

	counts := toMap(response.Data[0].Statuses)
	suite.Equal(int64(1), counts["satisfied"])
	suite.Equal(int64(0), counts["not-satisfied"])

	counts = toMap(response.Data[1].Statuses)
	suite.Equal(int64(0), counts["satisfied"])
	suite.Equal(int64(1), counts["not-satisfied"])

	counts = toMap(response.Data[2].Statuses)
	suite.Equal(int64(1), counts["satisfied"])
	suite.Equal(int64(0), counts["not-satisfied"])

	counts = toMap(response.Data[3].Statuses)
	suite.Equal(int64(0), counts["satisfied"])
	suite.Equal(int64(1), counts["not-satisfied"])
}

func (suite *EvidenceApiIntegrationSuite) TestComplianceByFilter() {
	suite.Run("Returns status counts for a filter", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create a filter
		filter := relational.Filter{
			Name: "Test Filter",
			Filter: datatypes.NewJSONType(labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			}),
		}
		suite.NoError(suite.DB.Create(&filter).Error)

		// Create evidence matching the filter
		evidence := []relational.Evidence{
			{
				UUID:   uuid.New(),
				Title:  "Satisfied Evidence",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "aws"},
				},
			},
			{
				UUID:   uuid.New(),
				Title:  "Not Satisfied Evidence",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "not-satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "aws"},
				},
			},
			{
				UUID:   uuid.New(),
				Title:  "Another Satisfied",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "aws"},
				},
			},
			{
				UUID:   uuid.New(),
				Title:  "Non-matching Evidence",
				Start:  time.Now().Add(-time.Hour),
				End:    time.Now().Add(-time.Hour).Add(time.Minute),
				Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
				Labels: []relational.Labels{
					{Name: "provider", Value: "github"},
				},
			},
		}
		suite.NoError(suite.DB.Create(&evidence).Error)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/evidence/compliance-by-filter/%s", filter.ID), nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		response := struct {
			Data []struct {
				Count  int64  `json:"count"`
				Status string `json:"status"`
			} `json:"data"`
		}{}
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)

		// Should have 2 satisfied and 1 not-satisfied (excluding the github one)
		statusCounts := make(map[string]int64)
		for _, s := range response.Data {
			statusCounts[s.Status] = s.Count
		}
		suite.Equal(int64(2), statusCounts["satisfied"])
		suite.Equal(int64(1), statusCounts["not-satisfied"])
	})

	suite.Run("Returns 404 for non-existent filter", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/evidence/compliance-by-filter/%s", uuid.New()), nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusNotFound, rec.Code)
	})

	suite.Run("Returns 400 for invalid UUID", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := &APIServices{}
		evidenceSvc := evidencesvc.NewEvidenceService(suite.DB, logger.Sugar(), suite.Config, nil)
		services.EvidenceService = evidenceSvc
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/evidence/compliance-by-filter/invalid-uuid", nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
	})
}
