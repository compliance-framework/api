//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestHealthApi(t *testing.T) {
	suite.Run(t, new(HealthApiIntegrationSuite))
}

type HealthApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *HealthApiIntegrationSuite) TestHealthEndpoint() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)

	NewHealthHandler(logger.Sugar(), suite.DB).Register(server.API().Group("/health"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response struct {
		Status string `json:"status"`
	}

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal("ok", response.Status)
}

func (suite *HealthApiIntegrationSuite) TestReadyEndpoint() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)

	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)

	NewHealthHandler(logger.Sugar(), suite.DB).Register(server.API().Group("/health"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health/ready", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusOK, rec.Code)

	var response struct {
		Status string `json:"status"`
	}

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal("ok", response.Status)
}

func (suite *HealthApiIntegrationSuite) TestReadyEndpointUnavailable() {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)

	NewHealthHandler(logger.Sugar(), nil).Register(server.API().Group("/health"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health/ready", nil)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	server.E().ServeHTTP(rec, req)

	suite.Equal(http.StatusServiceUnavailable, rec.Code)

	var response struct {
		Status string `json:"status"`
	}

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal("unavailable", response.Status)
}
