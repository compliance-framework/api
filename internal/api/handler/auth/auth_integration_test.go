//go:build integration

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestAuthAPI(t *testing.T) {
	suite.Run(t, new(AuthAPIIntegrationSuite))
}

type AuthAPIIntegrationSuite struct {
	tests.IntegrationTestSuite
	logger *zap.SugaredLogger
	server *api.Server
}

type loginResponse struct {
	Data struct {
		AuthToken string `json:"auth_token"`
	} `json:"data"`
}

type errorResponse struct {
	Data struct {
		Email []string `json:"email"`
	} `json:"data"`
}

func (suite *AuthAPIIntegrationSuite) SetupSuite() {
	fmt.Println("Setting up Auth API test suite")
	suite.IntegrationTestSuite.SetupSuite()

	// Setup logger and server once for all tests
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()
	suite.logger = logger.Sugar()
	metrics := api.NewMetricsHandler(context.Background(), suite.logger)
	suite.server = api.NewServer(context.Background(), suite.logger, suite.Config, metrics)
	RegisterHandlers(suite.server, suite.logger, suite.DB, suite.Config, metrics, nil, nil)
	fmt.Println("Server initialized")
}

func (suite *AuthAPIIntegrationSuite) TestLogin() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`{"email":"dummy@example.com","password":"Pa55w0rd"}`)))
	req.Header.Set("Content-Type", "application/json")
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

	var resp loginResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	suite.Require().NoError(err)
	suite.NotEmpty(resp.Data.AuthToken, "Expected non-empty auth token")

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "ccf_auth_token" {
			suite.NotEmpty(cookie.Value, "Expected ccf_auth_token cookie to be set")
			suite.Equal(true, cookie.HttpOnly, "Expected ccf_auth_token cookie to be HttpOnly")
			suite.Equal(true, cookie.Secure, "Expected ccf_auth_token cookie to be Secure")
			suite.Equal(resp.Data.AuthToken, cookie.Value, "Expected ccf_auth_token cookie value to match auth token")
		}
	}
}

func (suite *AuthAPIIntegrationSuite) TestLoginInvalidCredentials() {
	for _, testData := range []struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		{Email: "test@example.com", Password: "wrongPassword"},
		{Email: "invalid-email", Password: "Pa55w0rd"},
	} {
		payload, err := json.Marshal(testData)
		suite.Require().NoError(err, "Failed to marshal test data")

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		suite.server.E().ServeHTTP(rec, req)
		suite.Equal(http.StatusUnauthorized, rec.Code, "Expected status code 401 Unauthorized")

		var response errorResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		suite.Require().NoError(err)
		suite.Len(response.Data.Email, 1, "Expected one validation error for email")
	}
}

func (suite *AuthAPIIntegrationSuite) TestPublicKeyEndpoint() {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/publickey.pub", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, "Expected status code 200 OK")

	respKey, _ := pem.Decode(rec.Body.Bytes())
	suite.Require().NotNil(respKey, "Expected PEM-encoded public key in response")
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenWithBasicAuth() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	agent, err := suite.CreateAgent("auth-agent")
	suite.Require().NoError(err)
	key, secret, err := suite.CreateAgentKey(agent, "auth-key")
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", nil)
	req.SetBasicAuth(key.ClientID, secret)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	suite.Contains(rec.Body.String(), "access_token")
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenWithFormCredentials() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	agent, err := suite.CreateAgent("form-agent")
	suite.Require().NoError(err)
	key, secret, err := suite.CreateAgentKey(agent, "form-key")
	suite.Require().NoError(err)

	form := url.Values{}
	form.Set("client_id", key.ClientID)
	form.Set("client_secret", secret)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenRejectsBadSecret() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	agent, err := suite.CreateAgent("bad-secret-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "bad-secret-key")
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", nil)
	req.SetBasicAuth(key.ClientID, "wrong-secret")
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnauthorized, rec.Code)
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenRejectsUnknownClientID() {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", nil)
	req.SetBasicAuth("missing-client-id", "wrong-secret")
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnauthorized, rec.Code)
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenRejectsRevokedKey() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	agent, err := suite.CreateAgent("revoked-agent")
	suite.Require().NoError(err)
	key, secret, err := suite.CreateAgentKey(agent, "revoked-key")
	suite.Require().NoError(err)
	now := time.Now().UTC()
	key.RevokedAt = &now
	suite.Require().NoError(suite.DB.Save(key).Error)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", nil)
	req.SetBasicAuth(key.ClientID, secret)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusForbidden, rec.Code)
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenRejectsInactiveAgent() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	agent, err := suite.CreateAgent("inactive-agent")
	suite.Require().NoError(err)
	agent.IsActive = false
	suite.Require().NoError(suite.DB.Save(agent).Error)
	key, secret, err := suite.CreateAgentKey(agent, "inactive-key")
	suite.Require().NoError(err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", nil)
	req.SetBasicAuth(key.ClientID, secret)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusForbidden, rec.Code)
}

func (suite *AuthAPIIntegrationSuite) TestAgentTokenRejectsExpiredKey() {
	err := suite.IntegrationTestSuite.Migrator.Refresh()
	suite.Require().NoError(err)

	agent, err := suite.CreateAgent("expired-agent")
	suite.Require().NoError(err)
	key, secret, err := suite.CreateAgentKey(agent, "expired-key")
	suite.Require().NoError(err)
	expiresAt := time.Now().UTC().Add(-time.Minute)
	key.ExpiresAt = &expiresAt
	suite.Require().NoError(suite.DB.Save(key).Error)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/agent/token", nil)
	req.SetBasicAuth(key.ClientID, secret)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusForbidden, rec.Code)
}
