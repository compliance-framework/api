//go:build integration

package oscal

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
	apihandler "github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	"github.com/compliance-framework/api/internal/tests"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

type dashboardSuggestionFakeEnqueuer struct {
	runID     uuid.UUID
	cellCount int
	err       error
}

func (f *dashboardSuggestionFakeEnqueuer) EnqueueOrphanedRiskCleanup(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID) error {
	return nil
}

func (f *dashboardSuggestionFakeEnqueuer) EnqueueDashboardSuggestionCells(_ context.Context, runID uuid.UUID, cellCount int) error {
	f.runID = runID
	f.cellCount = cellCount
	return f.err
}

type DashboardSuggestionsHTTPSuite struct {
	tests.IntegrationTestSuite
	server   *api.Server
	enqueuer *dashboardSuggestionFakeEnqueuer
}

func TestDashboardSuggestionsHTTPSuite(t *testing.T) {
	suite.Run(t, new(DashboardSuggestionsHTTPSuite))
}

func (suite *DashboardSuggestionsHTTPSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
	suite.enqueuer = &dashboardSuggestionFakeEnqueuer{}
	suite.server = suite.newServer(true, suite.enqueuer, 0)
}

func (suite *DashboardSuggestionsHTTPSuite) newServer(enabled bool, enqueuer SSPJobEnqueuer, maxCalls int) *api.Server {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	cfg := *suite.Config
	cfg.AI = config.DefaultAIConfig()
	cfg.AI.Enabled = enabled
	cfg.AI.MaxControlsPerChunk = 1
	cfg.AI.MaxLabelSetsPerChunk = 1
	cfg.AI.MaxCallsPerRun = maxCalls
	server := api.NewServer(context.Background(), logger.Sugar(), &cfg, metrics)
	RegisterHandlers(server, logger.Sugar(), suite.DB, &cfg, nil, enqueuer)
	return server
}

func (suite *DashboardSuggestionsHTTPSuite) req(method, path string, body any) (*httptest.ResponseRecorder, *http.Request) {
	var buf []byte
	if body != nil {
		var err error
		buf, err = json.Marshal(body)
		suite.Require().NoError(err)
	}
	token, err := suite.GetAuthToken()
	suite.Require().NoError(err)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(buf))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization, fmt.Sprintf("Bearer %s", *token))
	return rec, req
}

func (suite *DashboardSuggestionsHTTPSuite) seedScope(controlIDs []string, labelSets []map[string]string) (uuid.UUID, []string, []string) {
	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	catalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.Create(&catalog).Error)
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)`,
		sspID, profileID,
	).Error)

	controlKeys := make([]string, 0, len(controlIDs))
	for _, controlID := range controlIDs {
		suite.Require().NoError(suite.DB.Create(&relational.Control{CatalogID: *catalog.ID, ID: controlID, Title: "Control " + controlID}).Error)
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
			profileID, catalog.ID, controlID,
		).Error)
		controlKeys = append(controlKeys, suggestionrel.ControlKey(*catalog.ID, controlID))
	}

	hashes := make([]string, 0, len(labelSets))
	for idx, labels := range labelSets {
		evidence := relational.Evidence{
			UUID:   uuid.New(),
			Title:  fmt.Sprintf("evidence-%d", idx),
			Start:  time.Now().UTC(),
			End:    time.Now().UTC(),
			Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		}
		suite.Require().NoError(suite.DB.Create(&evidence).Error)
		for key, value := range labels {
			suite.Require().NoError(suite.DB.Exec(
				`INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, ?, ?)`,
				evidence.ID, key, value,
			).Error)
		}
		normalized, ok := suggestionrel.NormalizeLabelSet(labels)
		suite.Require().True(ok)
		hashes = append(hashes, suggestionrel.CanonicalLabelSetHash(normalized))
	}
	return sspID, controlKeys, hashes
}

func (suite *DashboardSuggestionsHTTPSuite) TestGenerateCreatesRunCellsAndEnqueuesThenConflicts() {
	sspID, controlKeys, hashes := suite.seedScope([]string{"AC-1", "AC-2"}, []map[string]string{{"env": "prod"}, {"env": "stage"}})

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusAccepted, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[dashboardSuggestionRunResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(4, response.Data.PlannedCalls)
	suite.Equal(4, suite.enqueuer.cellCount)
	suite.Equal(*response.Data.ID, suite.enqueuer.runID)

	var cellCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRunCell{}).Where("run_id = ?", response.Data.ID).Count(&cellCount).Error)
	suite.Equal(int64(4), cellCount)
	suite.ElementsMatch(controlKeys, stringSliceFromJSONValue(response.Data.Scope["controlKeys"]))
	suite.ElementsMatch(hashes, stringSliceFromJSONValue(response.Data.Scope["labelSetHashes"]))

	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusConflict, rec.Code, rec.Body.String())
}

func (suite *DashboardSuggestionsHTTPSuite) TestGenerateValidationAndWorkerDisabledPaths() {
	sspID, _, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})

	body := generateDashboardSuggestionsRequest{Scope: &dashboardSuggestionScopeRequest{ControlKeys: []string{"missing"}}}
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnprocessableEntity, rec.Code, rec.Body.String())

	oversizedSSPID, _, _ := suite.seedScope([]string{"AC-2", "AC-3"}, []map[string]string{{"tier": "app"}})
	limitedServer := suite.newServer(true, suite.enqueuer, 1)
	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", oversizedSSPID), nil)
	limitedServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnprocessableEntity, rec.Code, rec.Body.String())

	disabledSSPID, _, _ := suite.seedScope([]string{"AC-4"}, []map[string]string{{"tier": "db"}})
	workerDisabledServer := suite.newServer(true, nil, 0)
	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", disabledSSPID), nil)
	workerDisabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusServiceUnavailable, rec.Code, rec.Body.String())
}

func (suite *DashboardSuggestionsHTTPSuite) TestFlagOffDoesNotRegisterScopedRoutesAndConfigReportsFalse() {
	disabledServer := suite.newServer(false, suite.enqueuer, 0)
	sspID, _, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/dashboard-suggestions/config", nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var response apihandler.GenericDataResponse[dashboardSuggestionConfigResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.False(response.Data.Enabled)
}

func stringSliceFromJSONValue(value any) []string {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok {
			out = append(out, value)
		}
	}
	return out
}
