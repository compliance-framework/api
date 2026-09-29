//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestPlaybackApi(t *testing.T) {
	suite.Run(t, new(PlaybackApiIntegrationSuite))
}

type PlaybackApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *PlaybackApiIntegrationSuite) setupServer() *api.Server {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, &APIServices{})
	return server
}

func (suite *PlaybackApiIntegrationSuite) evaluate(server *api.Server, token string) *httptest.ResponseRecorder {
	body, err := json.Marshal(map[string]any{
		"policy": playbackTestPolicy,
		"input":  map[string]any{"PermitRootLogin": "yes"},
	})
	suite.Require().NoError(err)

	req := httptest.NewRequest(http.MethodPost, "/api/playback/evaluate", strings.NewReader(string(body)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if token != "" {
		req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", token))
	}
	rec := httptest.NewRecorder()
	server.E().ServeHTTP(rec, req)
	return rec
}

func (suite *PlaybackApiIntegrationSuite) decodeResults(rec *httptest.ResponseRecorder) []policyeval.EvaluateResult {
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())
	var resp policyeval.EvaluateResponse
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Results
}

func (suite *PlaybackApiIntegrationSuite) agentToken() string {
	agent, err := suite.CreateAgent("playback-agent")
	suite.Require().NoError(err)
	key, _, err := suite.CreateAgentKey(agent, "playback-key")
	suite.Require().NoError(err)
	token, err := suite.GetAgentToken(agent, key)
	suite.Require().NoError(err)
	return *token
}

func (suite *PlaybackApiIntegrationSuite) TestUserAgentAndAnonymousGetTheSameResult() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.Config.StrictDisablePublicAgentEndpoints = false
	server := suite.setupServer()

	userToken, err := suite.GetAuthToken()
	suite.Require().NoError(err)

	fromUser := suite.decodeResults(suite.evaluate(server, *userToken))
	fromAgent := suite.decodeResults(suite.evaluate(server, suite.agentToken()))
	fromAnonymous := suite.decodeResults(suite.evaluate(server, ""))

	suite.Require().Len(fromUser, 1)
	suite.Equal(policyeval.StatusNotSatisfied, fromUser[0].Status)
	suite.Equal(fromUser, fromAgent)
	suite.Equal(fromUser, fromAnonymous)
}

func (suite *PlaybackApiIntegrationSuite) TestAnonymousRefusedWhenPublicAgentEndpointsDisabled() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.Config.StrictDisablePublicAgentEndpoints = true
	server := suite.setupServer()

	suite.Equal(http.StatusUnauthorized, suite.evaluate(server, "").Code)

	// Authenticated callers are unaffected by the strict setting.
	suite.decodeResults(suite.evaluate(server, suite.agentToken()))
}

func (suite *PlaybackApiIntegrationSuite) TestDisabledRemovesRoute() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.Config.StrictDisablePublicAgentEndpoints = false
	previous := suite.Config.Playback
	disabled := config.DefaultPlaybackConfig()
	disabled.Enabled = false
	suite.Config.Playback = disabled
	defer func() { suite.Config.Playback = previous }()

	server := suite.setupServer()
	suite.Equal(http.StatusNotFound, suite.evaluate(server, "").Code)
}
