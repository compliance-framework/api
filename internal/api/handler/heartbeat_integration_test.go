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
	"github.com/compliance-framework/api/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"github.com/compliance-framework/api/internal/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestHeartbeatApi(t *testing.T) {
	suite.Run(t, new(HeartbeatApiIntegrationSuite))
}

type HeartbeatApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *HeartbeatApiIntegrationSuite) setupServer() *api.Server {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	services := &APIServices{}
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
	return server
}

func (suite *HeartbeatApiIntegrationSuite) TestHeartbeatCreateValidation() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	// Create two catalogs with the same group ID structure
	heartbeat := HeartbeatCreateRequest{}
	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(heartbeat)
	req := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)
}

func (suite *HeartbeatApiIntegrationSuite) TestHeartbeatCreate() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = false

	// Create two catalogs with the same group ID structure
	heartbeat := HeartbeatCreateRequest{
		UUID:      uuid.New(),
		CreatedAt: time.Now(),
	}

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(heartbeat)
	req := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusCreated, rec.Code)

	var count int64
	// Counting users with specific names
	suite.DB.Model(&service.Heartbeat{}).Count(&count)
	suite.Equal(int64(1), count)
}

func (suite *HeartbeatApiIntegrationSuite) TestHeartbeatOverTime() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	// Seed some heartbeats
	for range 3 {
		id := uuid.New()
		for i := range 10 {
			suite.DB.Model(&service.Heartbeat{}).Create(&service.Heartbeat{
				UUID:      id,
				CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
			})
		}
	}

	// Create two catalogs with the same group ID structure
	server := suite.setupServer()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/heartbeat/over-time/", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusOK, rec.Code)

	response := struct {
		Data []struct {
			Interval time.Time
			Total    int
		} `json:"data"`
	}{}
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	suite.Require().NoError(err)

	fmt.Println(response.Data)

	suite.Len(response.Data, 6)            // There are 6 intervals
	suite.Equal(response.Data[0].Total, 3) // Each interval should have 3 agents
	suite.Equal(response.Data[1].Total, 3) // Each interval should have 3 agents
	suite.Equal(response.Data[2].Total, 3) // Each interval should have 3 agents

	// The interval gap should be 2 minutes
	suite.Equal(response.Data[0].Interval.Sub(response.Data[1].Interval).Abs(), 2*time.Minute)
	suite.Equal(response.Data[1].Interval.Sub(response.Data[2].Interval).Abs(), 2*time.Minute)
}

func (suite *HeartbeatApiIntegrationSuite) TestHeartbeatCreateRequiresAgentAuthWhenUnsafeDisabled() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
	suite.Config.StrictDisablePublicAgentEndpoints = true

	server := suite.setupServer()
	rec := httptest.NewRecorder()
	reqBody, _ := json.Marshal(HeartbeatCreateRequest{UUID: uuid.New(), CreatedAt: time.Now()})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/heartbeat", bytes.NewReader(reqBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)
	assert.Equal(suite.T(), http.StatusUnauthorized, rec.Code)
}
