//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event/bus"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/configuration-service/tests"
	"github.com/stretchr/testify/suite"
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
		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(context.TODO(), bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		resultsHandler := NewResultsHandler(logger.Sugar(), service.NewResultsService(suite.MongoDatabase), service.NewPlanService(suite.MongoDatabase, bus.Publish))
		server := api.NewServer(context.Background(), logger.Sugar())
		resultsHandler.Register(server.API().Group("/results"))
		// Create an empty plan
		planService := service.NewPlanService(suite.MongoDatabase, bus.Publish)
		planId, err := planService.Create(&domain.Plan{
			Id: primitive.NewObjectID(),
			ResultFilter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "foo",
						Operator: "=",
						Value:    "bar",
					},
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/results/plan/%s", planId), nil)
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

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(context.TODO(), bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Create an empty plan
		planService := service.NewPlanService(suite.MongoDatabase, bus.Publish)
		planId, err := planService.Create(&domain.Plan{
			Id: primitive.NewObjectID(),
			ResultFilter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "foo",
						Operator: "=",
						Value:    "bar",
					},
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Add a result
		resultService := service.NewResultsService(suite.MongoDatabase)
		err = resultService.Create(context.Background(), &domain.Result{
			StreamID: uuid.New(),
			Labels: map[string]string{
				"foo": "bar",
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		resultsHandler := NewResultsHandler(logger.Sugar(), resultService, planService)
		server := api.NewServer(context.Background(), logger.Sugar())
		resultsHandler.Register(server.API().Group("/results"))

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/results/plan/%s", planId), nil)
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
