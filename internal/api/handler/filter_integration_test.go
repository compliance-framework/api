//go:build integration

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/compliance-framework/configuration-service/internal/tests"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilterApi(t *testing.T) {
	suite.Run(t, new(FilterApiIntegrationSuite))
}

type FilterApiIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *FilterApiIntegrationSuite) TestCreate() {
	suite.Run("Simple", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		createReq := createFilterRequest{
			Name: "Simple Filter",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
		}

		logger, _ := zap.NewDevelopment()
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	})

	suite.Run("With Controls", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		suite.DB.Create(&relational.Catalog{
			Metadata: relational.Metadata{
				Title: "Some Catalog",
			},
			Controls: []relational.Control{
				{
					ID:    "AC-1",
					Title: "Access Control",
				},
			},
		})

		createReq := createFilterRequest{
			Name: "Simple Filter",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
			Controls: &[]string{
				"AC-1",
			},
		}

		logger, _ := zap.NewDevelopment()
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	})
}
