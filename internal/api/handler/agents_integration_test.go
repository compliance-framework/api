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

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type AgentAPIIntegrationSuite struct {
	tests.IntegrationTestSuite
	server *api.Server
}

func TestAgentAPI(t *testing.T) {
	suite.Run(t, new(AgentAPIIntegrationSuite))
}

func (suite *AgentAPIIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	suite.server = api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(suite.server, logger.Sugar(), suite.DB, suite.Config, &APIServices{})
}

func (suite *AgentAPIIntegrationSuite) authedRequest(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
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

func (suite *AgentAPIIntegrationSuite) TestAgentCRUDAndKeys() {
	createRec, createReq := suite.authedRequest(http.MethodPost, "/api/admin/agents", map[string]any{
		"name":        "agent-one",
		"description": "integration agent",
	})
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created GenericDataResponse[agentResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))
	require.Equal(suite.T(), "agent-one", created.Data.Name)
	require.Equal(suite.T(), int64(0), created.Data.ServiceAccountKeys)

	listRec, listReq := suite.authedRequest(http.MethodGet, "/api/admin/agents", nil)
	suite.server.E().ServeHTTP(listRec, listReq)
	require.Equal(suite.T(), http.StatusOK, listRec.Code)

	var listed GenericDataListResponse[agentResponse]
	require.NoError(suite.T(), json.Unmarshal(listRec.Body.Bytes(), &listed))
	require.Len(suite.T(), listed.Data, 1)

	getRec, getReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/agents/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(getRec, getReq)
	require.Equal(suite.T(), http.StatusOK, getRec.Code)

	updateRec, updateReq := suite.authedRequest(http.MethodPut, fmt.Sprintf("/api/admin/agents/%s", created.Data.ID), map[string]any{
		"name":      "agent-one-updated",
		"is-active": false,
	})
	suite.server.E().ServeHTTP(updateRec, updateReq)
	require.Equal(suite.T(), http.StatusOK, updateRec.Code)

	var updated GenericDataResponse[agentResponse]
	require.NoError(suite.T(), json.Unmarshal(updateRec.Body.Bytes(), &updated))
	require.Equal(suite.T(), "agent-one-updated", updated.Data.Name)
	require.False(suite.T(), updated.Data.IsActive)

	keyCreateRec, keyCreateReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/admin/agents/%s/keys", created.Data.ID), map[string]any{
		"name":          "primary",
		"never-expires": true,
	})
	suite.server.E().ServeHTTP(keyCreateRec, keyCreateReq)
	require.Equal(suite.T(), http.StatusCreated, keyCreateRec.Code)

	var keyCreated GenericDataResponse[agentKeyCreateResponse]
	require.NoError(suite.T(), json.Unmarshal(keyCreateRec.Body.Bytes(), &keyCreated))
	require.NotEmpty(suite.T(), keyCreated.Data.ClientID)
	require.NotEmpty(suite.T(), keyCreated.Data.ClientSecret)
	require.True(suite.T(), keyCreated.Data.NeverExpires)

	keyListRec, keyListReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/agents/%s/keys", created.Data.ID), nil)
	suite.server.E().ServeHTTP(keyListRec, keyListReq)
	require.Equal(suite.T(), http.StatusOK, keyListRec.Code)

	var keyList GenericDataListResponse[agentKeyResponse]
	require.NoError(suite.T(), json.Unmarshal(keyListRec.Body.Bytes(), &keyList))
	require.Len(suite.T(), keyList.Data, 1)
	require.Equal(suite.T(), keyCreated.Data.ClientID, keyList.Data[0].ClientID)
	require.True(suite.T(), keyList.Data[0].NeverExpires)

	keyGetRec, keyGetReq := suite.authedRequest(http.MethodGet, fmt.Sprintf("/api/admin/agents/%s/keys/%s", created.Data.ID, keyCreated.Data.ID), nil)
	suite.server.E().ServeHTTP(keyGetRec, keyGetReq)
	require.Equal(suite.T(), http.StatusOK, keyGetRec.Code)

	keyDeleteRec, keyDeleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/admin/agents/%s/keys/%s", created.Data.ID, keyCreated.Data.ID), nil)
	suite.server.E().ServeHTTP(keyDeleteRec, keyDeleteReq)
	require.Equal(suite.T(), http.StatusNoContent, keyDeleteRec.Code)

	deleteRec, deleteReq := suite.authedRequest(http.MethodDelete, fmt.Sprintf("/api/admin/agents/%s", created.Data.ID), nil)
	suite.server.E().ServeHTTP(deleteRec, deleteReq)
	require.Equal(suite.T(), http.StatusNoContent, deleteRec.Code)
}

func (suite *AgentAPIIntegrationSuite) TestCreateAgentKeyWithExpiry() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	createRec, createReq := suite.authedRequest(http.MethodPost, "/api/admin/agents", map[string]any{
		"name": "agent-two",
	})
	suite.server.E().ServeHTTP(createRec, createReq)
	require.Equal(suite.T(), http.StatusCreated, createRec.Code)

	var created GenericDataResponse[agentResponse]
	require.NoError(suite.T(), json.Unmarshal(createRec.Body.Bytes(), &created))

	expiresAt := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339)
	keyCreateRec, keyCreateReq := suite.authedRequest(http.MethodPost, fmt.Sprintf("/api/admin/agents/%s/keys", created.Data.ID), map[string]any{
		"name":       "expiring",
		"expires-at": expiresAt,
	})
	suite.server.E().ServeHTTP(keyCreateRec, keyCreateReq)
	require.Equal(suite.T(), http.StatusCreated, keyCreateRec.Code)

	var keyCreated GenericDataResponse[agentKeyCreateResponse]
	require.NoError(suite.T(), json.Unmarshal(keyCreateRec.Body.Bytes(), &keyCreated))
	require.False(suite.T(), keyCreated.Data.NeverExpires)
	require.NotNil(suite.T(), keyCreated.Data.ExpiresAt)
}
