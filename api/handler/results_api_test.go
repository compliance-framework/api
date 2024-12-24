//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event/bus"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/configuration-service/service"
	"github.com/compliance-framework/configuration-service/tests"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

func TestResultsApi(t *testing.T) {
	suite.Run(t, new(ResultsIntegrationSuite))
}

type ResultsIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *ResultsIntegrationSuite) TestGetPlanResults() {
	suite.Run("A plan with no results return and empty data key", func() {
		logger, _ := zap.NewProduction()
		resultsHandler := NewResultsHandler(logger.Sugar(), service.NewResultsService(suite.MongoDatabase))
		server := api.NewServer(context.Background(), logger.Sugar())
		resultsHandler.Register(server.API().Group("/results"))

		// Create an empty plan
		planService := service.NewPlanService(suite.MongoDatabase, bus.Publish)
		planId, err := planService.Create(&domain.Plan{
			Id: primitive.NewObjectID(),
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/results/%s", planId), nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		server.E().ServeHTTP(rec, req)

		assert.Equal(suite.T(), http.StatusOK, rec.Code, "Expected status 200 Created")

		response := &struct {
			Data []*domain.Result `json:"data"`
		}{}
		assert.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), response), "Failed to parse response from GetResults")
		assert.Equal(suite.T(), response.Data, make([]*domain.Result, 0), "Expected no data in data key")
	})

	suite.Run("A plan with a result returns it", func() {
		logger, _ := zap.NewProduction()

		// Create an empty plan
		planService := service.NewPlanService(suite.MongoDatabase, bus.Publish)
		planId, err := planService.Create(&domain.Plan{
			Id: primitive.NewObjectID(),
		})
		if err != nil {
			suite.T().Fatal(err)
		}
		planIdPrimitive, err := primitive.ObjectIDFromHex(planId)
		if err != nil {
			suite.T().Fatal(err)
		}

		// Add a result
		resultService := service.NewResultsService(suite.MongoDatabase)
		resultService.Create(context.Background(), &domain.Result{
			StreamID: uuid.New(),
			RelatedPlans: []*primitive.ObjectID{
				&planIdPrimitive,
			},
		})

		resultsHandler := NewResultsHandler(logger.Sugar(), resultService)
		server := api.NewServer(context.Background(), logger.Sugar())
		resultsHandler.Register(server.API().Group("/results"))

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/results/%s", planId), nil)
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		rec := httptest.NewRecorder()
		server.E().ServeHTTP(rec, req)

		assert.Equal(suite.T(), http.StatusOK, rec.Code, "Expected status 200 Created")

		response := &struct {
			Data []*domain.Result `json:"data"`
		}{}
		assert.NoError(suite.T(), json.Unmarshal(rec.Body.Bytes(), response), "Failed to parse response from GetResults")
		assert.Len(suite.T(), response.Data, 1, "Expected data in data key")
	})
}
