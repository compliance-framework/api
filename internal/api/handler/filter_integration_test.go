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

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
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
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
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
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	})
}

func (suite *FilterApiIntegrationSuite) TestUpdate() {
	suite.Run("Update filter name and filter", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create initial filter
		filter := relational.Filter{
			Name: "Original Filter",
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

		updateReq := createFilterRequest{
			Name: "Updated Filter",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "github",
					},
				},
			},
		}

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/filters/%s", filter.ID), bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		// Verify the update
		var updatedFilter relational.Filter
		suite.NoError(suite.DB.First(&updatedFilter, "id = ?", filter.ID).Error)
		suite.Equal("Updated Filter", updatedFilter.Name)
	})

	suite.Run("Update filter with controls", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create controls
		suite.DB.Create(&relational.Catalog{
			Metadata: relational.Metadata{
				Title: "Some Catalog",
			},
			Controls: []relational.Control{
				{ID: "AC-1", Title: "Access Control 1"},
				{ID: "AC-2", Title: "Access Control 2"},
				{ID: "AC-3", Title: "Access Control 3"},
			},
		})

		// Create initial filter with AC-1
		filter := relational.Filter{
			Name: "Filter With Controls",
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

		// Link AC-1 to the filter
		var control1 relational.Control
		suite.NoError(suite.DB.First(&control1, "id = ?", "AC-1").Error)
		suite.NoError(suite.DB.Model(&filter).Association("Controls").Append(&control1))

		// Verify initial state
		var initialFilter relational.Filter
		suite.NoError(suite.DB.Preload("Controls").First(&initialFilter, "id = ?", filter.ID).Error)
		suite.Len(initialFilter.Controls, 1)
		suite.Equal("AC-1", initialFilter.Controls[0].ID)

		// Update to have AC-2 and AC-3 instead
		updateReq := createFilterRequest{
			Name: "Filter With Controls",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
			Controls: &[]string{"AC-2", "AC-3"},
		}

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/filters/%s", filter.ID), bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		// Verify the controls were updated
		var updatedFilter relational.Filter
		suite.NoError(suite.DB.Preload("Controls").First(&updatedFilter, "id = ?", filter.ID).Error)
		suite.Len(updatedFilter.Controls, 2)

		controlIDs := make([]string, len(updatedFilter.Controls))
		for i, c := range updatedFilter.Controls {
			controlIDs[i] = c.ID
		}
		suite.Contains(controlIDs, "AC-2")
		suite.Contains(controlIDs, "AC-3")
		suite.NotContains(controlIDs, "AC-1")
	})

	suite.Run("Update filter without controls does not change existing controls", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create controls
		suite.DB.Create(&relational.Catalog{
			Metadata: relational.Metadata{
				Title: "Some Catalog",
			},
			Controls: []relational.Control{
				{ID: "AC-1", Title: "Access Control 1"},
			},
		})

		// Create initial filter with AC-1
		filter := relational.Filter{
			Name: "Filter With Controls",
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

		// Link AC-1 to the filter
		var control1 relational.Control
		suite.NoError(suite.DB.First(&control1, "id = ?", "AC-1").Error)
		suite.NoError(suite.DB.Model(&filter).Association("Controls").Append(&control1))

		// Update without specifying controls
		updateReq := createFilterRequest{
			Name: "Updated Name Only",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
			// Controls not specified
		}

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/filters/%s", filter.ID), bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		// Verify the controls were NOT changed
		var updatedFilter relational.Filter
		suite.NoError(suite.DB.Preload("Controls").First(&updatedFilter, "id = ?", filter.ID).Error)
		suite.Equal("Updated Name Only", updatedFilter.Name)
		suite.Len(updatedFilter.Controls, 1)
		suite.Equal("AC-1", updatedFilter.Controls[0].ID)
	})
}
