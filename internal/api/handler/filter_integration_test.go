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
	"github.com/google/uuid"
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
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
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
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	})

	suite.Run("With Components", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)
		id := uuid.New()
		suite.DB.Create(&relational.SystemComponent{
			UUIDModel: relational.UUIDModel{
				ID: &id,
			},
			Type:        "service",
			Title:       "Some System Component",
			Description: "blah blah blah",
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
			Components: &[]string{
				id.String(),
			},
		}

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(createReq)
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)
	})
}

func (suite *FilterApiIntegrationSuite) TestList() {
	suite.Run("Filters by control ID", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Seed catalog and controls
		suite.DB.Create(&relational.Catalog{
			Metadata: relational.Metadata{
				Title: "Some Catalog",
			},
			Controls: []relational.Control{
				{ID: "AC-1", Title: "Access Control 1"},
				{ID: "AC-2", Title: "Access Control 2"},
			},
		})

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)

		// Create filter linked to AC-1
		withControlReq := createFilterRequest{
			Name: "Linked Filter",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
			Controls: &[]string{"AC-1"},
		}
		body, _ := json.Marshal(withControlReq)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)

		// Create filter without controls
		withoutControlReq := createFilterRequest{
			Name: "Unlinked Filter",
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
		body, _ = json.Marshal(withoutControlReq)
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)

		// Fetch filters linked to AC-1
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/api/filters?controlId=AC-1", nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		var listResponse GenericDataListResponse[FilterWithAssociations]
		err = json.Unmarshal(rec.Body.Bytes(), &listResponse)
		suite.Require().NoError(err)

		assert.Len(suite.T(), listResponse.Data, 1)
		assert.Equal(suite.T(), "Linked Filter", listResponse.Data[0].Name)
		if assert.Len(suite.T(), listResponse.Data[0].Controls, 1) {
			assert.Equal(suite.T(), "AC-1", listResponse.Data[0].Controls[0].ID)
		}
	})

	suite.Run("Filters by component ID", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Seed component
		id := uuid.New()
		suite.DB.Create(&relational.SystemComponent{
			UUIDModel: relational.UUIDModel{
				ID: &id,
			},
			Type:        "service",
			Title:       "Some System Component",
			Description: "blah blah blah",
		})

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)

		// Create filter linked to our system component
		withComponentReq := createFilterRequest{
			Name: "Linked Filter",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
			Components: &[]string{id.String()},
		}
		body, _ := json.Marshal(withComponentReq)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)

		// Create filter without component
		withoutComponentReq := createFilterRequest{
			Name: "Unlinked Filter",
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
		body, _ = json.Marshal(withoutComponentReq)
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/api/filters", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusCreated, rec.Code)

		// Fetch filters linked to our component
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/filters?componentId=%s", id.String()), nil)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		var listResponse GenericDataListResponse[FilterWithAssociations]
		err = json.Unmarshal(rec.Body.Bytes(), &listResponse)
		suite.Require().NoError(err)

		assert.Len(suite.T(), listResponse.Data, 1)
		assert.Equal(suite.T(), "Linked Filter", listResponse.Data[0].Name)
		if assert.Len(suite.T(), listResponse.Data[0].Components, 1) {
			assert.Equal(suite.T(), id.String(), listResponse.Data[0].Components[0].UUID)
		}
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
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
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

	suite.Run("Update filter with controls and components", func() {
		err := suite.Migrator.Refresh()
		suite.Require().NoError(err)

		// Create initial filter
		filter := relational.Filter{
			Name: "Filter",
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

		// Verify initial state
		var initialFilter relational.Filter
		suite.NoError(suite.DB.Preload("Controls").Preload("Components").First(&initialFilter, "id = ?", filter.ID).Error)
		suite.Len(initialFilter.Controls, 0)
		suite.Len(initialFilter.Components, 0)

		// Update to have both controls and components
		updateReq := createFilterRequest{
			Name: "Filter",
			Filter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "provider",
						Operator: "=",
						Value:    "aws",
					},
				},
			},
			Controls:   &[]string{"AC-1"},
			Components: &[]string{uuid.NewString()},
		}

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/filters/%s", filter.ID), bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusBadRequest, rec.Code)

		// Verify the filter was not changed
		var updatedFilter relational.Filter
		suite.NoError(suite.DB.Preload("Controls").Preload("Components").First(&updatedFilter, "id = ?", filter.ID).Error)
		suite.Len(updatedFilter.Controls, 0)
		suite.Len(updatedFilter.Components, 0)
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
		suite.NoError(suite.DB.Preload("Controls").Preload("Components").First(&initialFilter, "id = ?", filter.ID).Error)
		suite.Len(initialFilter.Controls, 1)
		suite.Equal("AC-1", initialFilter.Controls[0].ID)
		suite.Len(initialFilter.Components, 0)

		// Update to have AC-2, AC-3
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
			Controls:   &[]string{"AC-2", "AC-3"},
			Components: &[]string{},
		}

		logger, _ := zap.NewDevelopment()
		metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
		server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
		rec := httptest.NewRecorder()
		reqBody, _ := json.Marshal(updateReq)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/filters/%s", filter.ID), bytes.NewReader(reqBody))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		server.E().ServeHTTP(rec, req)
		assert.Equal(suite.T(), http.StatusOK, rec.Code)

		// Verify the controls were updated
		var updatedFilter relational.Filter
		suite.NoError(suite.DB.Preload("Controls").Preload("Components").First(&updatedFilter, "id = ?", filter.ID).Error)
		suite.Len(updatedFilter.Controls, 2)
		suite.Len(updatedFilter.Components, 0)

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
		services := NewEmptyAPIServices()
		RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, services)
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
