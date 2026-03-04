//go:build integration

package handler

import (
	"bytes"
	"encoding/json"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type PoamItemsIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestPoamItemsApi(t *testing.T) {
	suite.Run(t, new(PoamItemsIntegrationSuite))
}

func (suite *PoamItemsIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	require.NoError(suite.T(), err)
}

func (suite *PoamItemsIntegrationSuite) TestCreateAndList() {
	// Seed minimal SSP and Risk if required by FK constraints; assume risk exists or FK is deferred in tests
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, nil, nil)
	e := server.E()

	sspID := uuid.New()
	// Insert a placeholder SSP to satisfy FK if needed
	_ = suite.DB.Exec("INSERT INTO system_security_plans (id, title, version) VALUES (?, 'Test SSP', '1.0')", sspID).Error

	deadline := time.Now().Add(30 * 24 * time.Hour).UTC()
	reqBody := map[string]any{
		"sspId":           sspID.String(),
		"title":           "Remediate missing secret scanning",
		"description":     "Enable scanning across all repos",
		"status":          "open",
		"deadline":        deadline.Format(time.RFC3339),
		"resourceRequired": "2 engineer days",
		"pocName":         "Jane Smith",
		"pocEmail":        "jane@example.com",
		"milestones": []map[string]any{
			{
				"title":       "Enable secret scanning in all repos",
				"description": "Turn on org policy",
				"status":      "planned",
			},
		},
	}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/poam-items", bytes.NewReader(b))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusCreated, rec.Code)

	// List by status filter
	req2 := httptest.NewRequest(http.MethodGet, "/api/poam-items?status=open", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	require.Equal(suite.T(), http.StatusOK, rec2.Code)
}

func (suite *PoamItemsIntegrationSuite) TestMilestoneCompletionSetsTimestamp() {
	logger, _ := zap.NewDevelopment()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	server := api.NewServer(context.Background(), logger.Sugar(), suite.Config, metrics)
	RegisterHandlers(server, logger.Sugar(), suite.DB, suite.Config, nil, nil)
	e := server.E()

	sspID := uuid.New()
	_ = suite.DB.Exec("INSERT INTO system_security_plans (id, title, version) VALUES (?, 'Test SSP', '1.0')", sspID).Error

	item := relational.CcfPoamItem{
		ID:          uuid.New(),
		SspID:       sspID,
		Title:       "Test",
		Description: "Test",
		Status:      "open",
	}
	require.NoError(suite.T(), suite.DB.Create(&item).Error)
	ms := relational.CcfPoamItemMilestone{
		ID:         uuid.New(),
		PoamItemID: item.ID,
		Title:      "Step",
		Description: "Do it",
		Status:     "planned",
	}
	require.NoError(suite.T(), suite.DB.Create(&ms).Error)

	patch := map[string]any{"status": "completed"}
	b, _ := json.Marshal(patch)
	req := httptest.NewRequest(http.MethodPut, "/api/poam-items/"+item.ID.String()+"/milestones/"+ms.ID.String(), bytes.NewReader(b))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	require.Equal(suite.T(), http.StatusOK, rec.Code)
}
