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
	workersvc "github.com/compliance-framework/api/internal/service/worker"
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
	calls     int
	err       error
}

func (f *dashboardSuggestionFakeEnqueuer) EnqueueOrphanedRiskCleanup(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID) error {
	return nil
}

func (f *dashboardSuggestionFakeEnqueuer) EnqueueDashboardSuggestionCells(_ context.Context, runID uuid.UUID, cellCount int) error {
	f.calls++
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
	return suite.newServerWithChunks(enabled, enqueuer, maxCalls, 1, 1)
}

func (suite *DashboardSuggestionsHTTPSuite) newServerWithChunks(enabled bool, enqueuer SSPJobEnqueuer, maxCalls int, maxControlsPerChunk int, maxLabelSetsPerChunk int) *api.Server {
	logConf := zap.NewDevelopmentConfig()
	logConf.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	logger, _ := logConf.Build()
	metrics := api.NewMetricsHandler(context.Background(), logger.Sugar())
	cfg := *suite.Config
	cfg.AI = config.DefaultAIConfig()
	cfg.AI.Enabled = enabled
	cfg.AI.MaxControlsPerChunk = maxControlsPerChunk
	cfg.AI.MaxLabelSetsPerChunk = maxLabelSetsPerChunk
	cfg.AI.MaxCallsPerRun = maxCalls
	server := api.NewServer(context.Background(), logger.Sugar(), &cfg, metrics)
	RegisterHandlers(server, logger.Sugar(), suite.DB, &cfg, nil, enqueuer, nil)
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

func (suite *DashboardSuggestionsHTTPSuite) TestPreviewReturnsChunkedPlanAndLeavesNoGenerationState() {
	controlIDs := make([]string, 0, 16)
	for idx := 1; idx <= 16; idx++ {
		controlIDs = append(controlIDs, fmt.Sprintf("AC-%d", idx))
	}
	labelSets := make([]map[string]string, 0, 47)
	for idx := 1; idx <= 47; idx++ {
		labelSets = append(labelSets, map[string]string{"env": fmt.Sprintf("env-%d", idx)})
	}
	sspID, controlKeys, hashes := suite.seedScope(controlIDs, labelSets)
	server := suite.newServerWithChunks(true, suite.enqueuer, 0, 40, 200)

	body := generateDashboardSuggestionsRequest{
		Scope: &dashboardSuggestionScopeRequest{
			ControlKeys:    controlKeys,
			LabelSetHashes: hashes,
		},
	}
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/preview", sspID), body)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[dashboardSuggestionPreviewResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(1, response.Data.PlannedCalls)
	suite.Equal(16, response.Data.ControlCount)
	suite.Equal(47, response.Data.LabelSetCount)
	suite.Equal(0, response.Data.MaxCallsPerRun)
	suite.False(response.Data.ExceedsLimit)
	suite.Equal(0, suite.enqueuer.calls)

	var runCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRun{}).Where("ssp_id = ?", sspID).Count(&runCount).Error)
	suite.Equal(int64(0), runCount)

	var cellCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Joins("JOIN dashboard_suggestion_runs ON dashboard_suggestion_runs.id = dashboard_suggestion_run_cells.run_id").
		Where("dashboard_suggestion_runs.ssp_id = ?", sspID).
		Count(&cellCount).Error)
	suite.Equal(int64(0), cellCount)

	var eventCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).Count(&eventCount).Error)
	suite.Equal(int64(0), eventCount)
}

func (suite *DashboardSuggestionsHTTPSuite) TestPreviewReportsConfiguredMaxCallsLimit() {
	sspID, controlKeys, hashes := suite.seedScope([]string{"AC-1", "AC-2"}, []map[string]string{{"env": "prod"}})
	body := generateDashboardSuggestionsRequest{
		Scope: &dashboardSuggestionScopeRequest{
			ControlKeys:    controlKeys,
			LabelSetHashes: hashes,
		},
	}

	limitedServer := suite.newServerWithChunks(true, suite.enqueuer, 1, 1, 1)
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/preview", sspID), body)
	limitedServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[dashboardSuggestionPreviewResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(2, response.Data.PlannedCalls)
	suite.Equal(2, response.Data.ControlCount)
	suite.Equal(1, response.Data.LabelSetCount)
	suite.Equal(1, response.Data.MaxCallsPerRun)
	suite.True(response.Data.ExceedsLimit)

	atLimitServer := suite.newServerWithChunks(true, suite.enqueuer, 2, 1, 1)
	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/preview", sspID), body)
	atLimitServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(2, response.Data.PlannedCalls)
	suite.Equal(2, response.Data.MaxCallsPerRun)
	suite.False(response.Data.ExceedsLimit)
	suite.Equal(0, suite.enqueuer.calls)
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

func (suite *DashboardSuggestionsHTTPSuite) TestGenerateWorkerNotRegisteredReturnsServiceUnavailableAndRollsBack() {
	sspID, _, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})
	enqueuer := &dashboardSuggestionFakeEnqueuer{err: workersvc.ErrDashboardSuggestionWorkerNotRegistered}
	server := suite.newServer(true, enqueuer, 0)

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	suite.Contains(rec.Body.String(), workersvc.ErrDashboardSuggestionWorkerNotRegistered.Error())

	var runCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRun{}).Where("ssp_id = ?", sspID).Count(&runCount).Error)
	suite.Equal(int64(0), runCount)

	var cellCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Joins("JOIN dashboard_suggestion_runs ON dashboard_suggestion_runs.id = dashboard_suggestion_run_cells.run_id").
		Where("dashboard_suggestion_runs.ssp_id = ?", sspID).
		Count(&cellCount).Error)
	suite.Equal(int64(0), cellCount)
}

func (suite *DashboardSuggestionsHTTPSuite) TestGenerateWorkerDisabledSentinelReturnsServiceUnavailableAndRollsBack() {
	sspID, _, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})
	enqueuer := &dashboardSuggestionFakeEnqueuer{err: workersvc.ErrDashboardSuggestionWorkerDisabled}
	server := suite.newServer(true, enqueuer, 0)

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	suite.Contains(rec.Body.String(), ErrDashboardSuggestionWorkerDisabled.Error())

	var runCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRun{}).Where("ssp_id = ?", sspID).Count(&runCount).Error)
	suite.Equal(int64(0), runCount)

	var cellCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Joins("JOIN dashboard_suggestion_runs ON dashboard_suggestion_runs.id = dashboard_suggestion_run_cells.run_id").
		Where("dashboard_suggestion_runs.ssp_id = ?", sspID).
		Count(&cellCount).Error)
	suite.Equal(int64(0), cellCount)
}

func (suite *DashboardSuggestionsHTTPSuite) TestGenerateRejectsEmptyResolvedScopeWithoutCreatingRun() {
	sspID, _, _ := suite.seedScope(nil, nil)

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
	suite.Contains(rec.Body.String(), "no controls resolved for dashboard suggestions")
	suite.Equal(0, suite.enqueuer.calls)

	var runCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRun{}).Where("ssp_id = ?", sspID).Count(&runCount).Error)
	suite.Equal(int64(0), runCount)

	var cellCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Joins("JOIN dashboard_suggestion_runs ON dashboard_suggestion_runs.id = dashboard_suggestion_run_cells.run_id").
		Where("dashboard_suggestion_runs.ssp_id = ?", sspID).
		Count(&cellCount).Error)
	suite.Equal(int64(0), cellCount)

	var profileIDRaw string
	suite.Require().NoError(suite.DB.Raw(`SELECT profile_id FROM ssp_profiles WHERE system_security_plan_id = ? LIMIT 1`, sspID).Scan(&profileIDRaw).Error)
	profileID, err := uuid.Parse(profileIDRaw)
	suite.Require().NoError(err)
	catalog := relational.Catalog{}
	suite.Require().NoError(suite.DB.First(&catalog).Error)
	suite.Require().NoError(suite.DB.Create(&relational.Control{CatalogID: *catalog.ID, ID: "AC-1", Title: "Control AC-1"}).Error)
	suite.Require().NoError(suite.DB.Exec(
		`INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)`,
		profileID, catalog.ID, "AC-1",
	).Error)
	evidence := relational.Evidence{
		UUID:   uuid.New(),
		Title:  "evidence-valid-after-empty-scope",
		Start:  time.Now().UTC(),
		End:    time.Now().UTC(),
		Status: datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: "satisfied"}),
		Labels: []relational.Labels{
			{Name: "env", Value: "prod"},
		},
	}
	suite.Require().NoError(suite.DB.Create(&evidence).Error)

	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusAccepted, rec.Code, rec.Body.String())
	suite.Equal(1, suite.enqueuer.calls)
}

func (suite *DashboardSuggestionsHTTPSuite) TestFlagOffDoesNotRegisterScopedRoutesAndConfigReportsFalse() {
	disabledServer := suite.newServer(false, suite.enqueuer, 0)
	sspID, _, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)

	rec, req = suite.req(http.MethodGet, "/api/dashboard-suggestions/config", nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var response apihandler.GenericDataResponse[dashboardSuggestionConfigResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.False(response.Data.Enabled)

	rec, req = suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/control-results", sspID), nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)
}

func (suite *DashboardSuggestionsHTTPSuite) TestControlResultsAuthEmptyAndLatestPerControl() {
	sspID, controlKeys, _ := suite.seedScope([]string{"AC-1", "AC-2"}, []map[string]string{{"env": "prod"}})
	catalogID, _ := suite.parseControlKey(controlKeys[0])

	rec, req := suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/control-results", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var empty apihandler.GenericDataListResponse[controlSuggestionResultResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &empty))
	suite.Empty(empty.Data)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/control-results", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnauthorized, rec.Code)

	oldStartedAt := time.Now().UTC().Add(-2 * time.Hour)
	newStartedAt := time.Now().UTC().Add(-1 * time.Hour)
	oldRunID := suite.seedSuggestionRunStartedAt(sspID, oldStartedAt)
	newRunID := suite.seedSuggestionRunStartedAt(sspID, newStartedAt)
	oldEvaluatedAt := oldStartedAt.Add(time.Minute)
	newEvaluatedAt := newStartedAt.Add(time.Minute)
	suite.seedControlResult(oldRunID, sspID, catalogID, "AC-1", suggestionrel.DashboardSuggestionControlOutcomeMatched, 1, oldEvaluatedAt)
	suite.seedControlResult(oldRunID, sspID, catalogID, "AC-2", suggestionrel.DashboardSuggestionControlOutcomeNoMatch, 0, oldEvaluatedAt)
	suite.seedControlResult(newRunID, sspID, catalogID, "AC-1", suggestionrel.DashboardSuggestionControlOutcomeNoMatch, 0, newEvaluatedAt)

	rec, req = suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/control-results", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var response apihandler.GenericDataListResponse[controlSuggestionResultResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Require().Len(response.Data, 2)
	byControl := map[string]controlSuggestionResultResponse{}
	for _, result := range response.Data {
		byControl[result.ControlID] = result
	}
	suite.Equal(newRunID, byControl["AC-1"].RunID)
	suite.Equal(suggestionrel.DashboardSuggestionControlOutcomeNoMatch, byControl["AC-1"].Outcome)
	suite.Equal(0, byControl["AC-1"].SuggestionCount)
	suite.Equal(catalogID, byControl["AC-1"].ControlCatalogID)
	suite.NotNil(byControl["AC-1"].EvaluatedAt)
	suite.Equal(oldRunID, byControl["AC-2"].RunID)
	suite.Equal(suggestionrel.DashboardSuggestionControlOutcomeNoMatch, byControl["AC-2"].Outcome)
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsSummaryTotalsAndCacheCheckTransition() {
	sspID := suite.seedDiagnosticsSSP("Diagnostics SSP")
	actorID := suite.dummyUserID()
	startedAt := time.Now().UTC().Add(-30 * time.Minute)
	completedAt := startedAt.Add(2 * time.Minute)
	runID := suite.seedDiagnosticsRun(sspID, "completed", startedAt, &completedAt, actorID, 100, 25, 0, 40, 2)
	suite.seedDiagnosticsCell(runID, 0, "completed", 100, 25, 0, 40, 2, 3, 1)
	suite.seedDiagnosticsSuggestion(runID, sspID, suggestionrel.DashboardSuggestionStatusAccepted)
	suite.seedDiagnosticsSuggestion(runID, sspID, suggestionrel.DashboardSuggestionStatusRejected)
	suite.seedDiagnosticsSuggestion(runID, sspID, suggestionrel.DashboardSuggestionStatusPending)

	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[AiDiagnosticsSummary]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.True(response.Data.Enabled)
	suite.Equal(suggestionrel.PromptVersion, response.Data.Config.PromptVersion)
	suite.Equal(int64(1), response.Data.Totals.Runs)
	suite.Equal(int64(1), response.Data.Totals.RunsByStatus["completed"])
	suite.Equal(int64(1), response.Data.Totals.CellsCompleted)
	suite.Equal(int64(100), response.Data.Totals.InputTokens)
	suite.Equal(int64(40), response.Data.Totals.CacheCreationInputTokens)
	suite.Equal(int64(2), response.Data.Totals.RateLimitedTotal)
	suite.Equal(int64(1), response.Data.Totals.SuggestionsAccepted)
	suite.Equal("warn", diagnosticsCheckStatus(response.Data.Checks, "cache_engaging"))
	suite.Equal("warn", diagnosticsCheckStatus(response.Data.Checks, "queue_reachable"))
	suite.Nil(response.Data.Queue)

	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Where("run_id = ? AND cell_index = ?", runID, 0).
		Update("cache_read_input_tokens", 20).Error)
	rec, req = suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(int64(20), response.Data.Totals.CacheReadInputTokens)
	suite.InDelta(0.125, response.Data.Totals.CacheHitRatio, 0.0001)
	suite.Equal("pass", diagnosticsCheckStatus(response.Data.Checks, "cache_engaging"))
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsSummaryQueueSuccessPath() {
	suite.Require().NoError(suite.DB.Exec(`DROP TABLE IF EXISTS river_job`).Error)
	suite.Require().NoError(suite.DB.Exec(`
		CREATE TABLE river_job (
			id bigserial PRIMARY KEY,
			kind text NOT NULL DEFAULT 'test',
			queue text NOT NULL,
			state text NOT NULL,
			scheduled_at timestamptz NOT NULL,
			finalized_at timestamptz NULL
		)
	`).Error)
	defer suite.DB.Exec(`DROP TABLE IF EXISTS river_job`)

	now := time.Now().UTC().Truncate(time.Second)
	oldest := now.Add(-30 * time.Minute)
	rows := []struct {
		queue       string
		state       string
		scheduledAt time.Time
		finalizedAt *time.Time
	}{
		{queue: aiDiagnosticsQueueName, state: "available", scheduledAt: oldest},
		{queue: aiDiagnosticsQueueName, state: "available", scheduledAt: now.Add(-10 * time.Minute)},
		{queue: aiDiagnosticsQueueName, state: "running", scheduledAt: now.Add(-9 * time.Minute)},
		{queue: aiDiagnosticsQueueName, state: "retryable", scheduledAt: now.Add(-8 * time.Minute)},
		{queue: aiDiagnosticsQueueName, state: "scheduled", scheduledAt: now.Add(-7 * time.Minute)},
		{queue: aiDiagnosticsQueueName, state: "completed", scheduledAt: now.Add(-6 * time.Minute), finalizedAt: ptrTime(now.Add(-5 * time.Minute))},
		{queue: aiDiagnosticsQueueName, state: "discarded", scheduledAt: now.Add(-4 * time.Minute), finalizedAt: ptrTime(now.Add(-3 * time.Minute))},
		{queue: "other", state: "available", scheduledAt: now.Add(-1 * time.Hour)},
		{queue: "other", state: "completed", scheduledAt: now.Add(-1 * time.Hour), finalizedAt: ptrTime(now.Add(-2 * time.Minute))},
	}
	for _, row := range rows {
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO river_job (queue, state, scheduled_at, finalized_at) VALUES (?, ?, ?, ?)`,
			row.queue,
			row.state,
			row.scheduledAt,
			row.finalizedAt,
		).Error)
	}

	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[AiDiagnosticsSummary]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Require().NotNil(response.Data.Queue)
	suite.Equal("pass", diagnosticsCheckStatus(response.Data.Checks, "queue_reachable"))
	suite.Equal(aiDiagnosticsQueueName, response.Data.Queue.Name)
	suite.Equal(int64(2), response.Data.Queue.Available)
	suite.Equal(int64(1), response.Data.Queue.Running)
	suite.Equal(int64(1), response.Data.Queue.Retryable)
	suite.Equal(int64(1), response.Data.Queue.Scheduled)
	suite.Equal(int64(1), response.Data.Queue.Completed24h)
	suite.Equal(int64(1), response.Data.Queue.Discarded24h)
	suite.Require().NotNil(response.Data.Queue.OldestAvailableAt)
	suite.WithinDuration(oldest, *response.Data.Queue.OldestAvailableAt, time.Second)
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsUsesCellTotalsForRunningRun() {
	sspID := suite.seedDiagnosticsSSP("Live Diagnostics SSP")
	actorID := suite.dummyUserID()
	startedAt := time.Now().UTC().Add(-10 * time.Minute)
	runID := suite.seedDiagnosticsRun(sspID, "running", startedAt, nil, actorID, 0, 0, 0, 0, 0)
	suite.seedDiagnosticsCell(runID, 0, "completed", 100, 25, 20, 40, 0, 3, 1)
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRunCell{
		RunID:            runID,
		CellIndex:        1,
		ControlKeys:      datatypes.NewJSONSlice([]string{"catalog:AC-2"}),
		LabelSetHashes:   datatypes.NewJSONSlice([]string{"hash"}),
		Status:           "pending",
		RateLimitedCount: 5,
	}).Error)

	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var summary apihandler.GenericDataResponse[AiDiagnosticsSummary]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &summary))
	suite.Equal(int64(100), summary.Data.Totals.InputTokens)
	suite.Equal(int64(25), summary.Data.Totals.OutputTokens)
	suite.Equal(int64(20), summary.Data.Totals.CacheReadInputTokens)
	suite.Equal(int64(40), summary.Data.Totals.CacheCreationInputTokens)
	suite.Equal(int64(5), summary.Data.Totals.RateLimitedTotal)
	suite.Equal("warn", diagnosticsCheckStatus(summary.Data.Checks, "rate_limit_pressure"))

	rec, req = suite.req(http.MethodGet, "/api/admin/ai-diagnostics/runs?status=running", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var list struct {
		Data []AiDiagnosticsRun    `json:"data"`
		Meta aiDiagnosticsListMeta `json:"meta"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	suite.Require().Len(list.Data, 1)
	suite.Equal(runID.String(), list.Data[0].ID)
	suite.Equal(100, list.Data[0].InputTokens)
	suite.Equal(25, list.Data[0].OutputTokens)
	suite.Equal(20, list.Data[0].CacheReadInputTokens)
	suite.Equal(40, list.Data[0].CacheCreationInputTokens)
	suite.Equal(5, list.Data[0].RateLimitedTotal)
	suite.InDelta(0.125, list.Data[0].CacheHitRatio, 0.0001)
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsRateLimitPressureWarnsForPendingOnlySnoozes() {
	sspID := suite.seedDiagnosticsSSP("Pending Throttle SSP")
	actorID := suite.dummyUserID()
	startedAt := time.Now().UTC().Add(-10 * time.Minute)
	runID := suite.seedDiagnosticsRun(sspID, "running", startedAt, nil, actorID, 0, 0, 0, 0, 0)
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRunCell{
		RunID:            runID,
		CellIndex:        0,
		ControlKeys:      datatypes.NewJSONSlice([]string{"catalog:AC-1"}),
		LabelSetHashes:   datatypes.NewJSONSlice([]string{"hash"}),
		Status:           "pending",
		RateLimitedCount: 5,
	}).Error)

	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[AiDiagnosticsSummary]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal(int64(0), response.Data.Totals.CellsCompleted)
	suite.Equal(int64(0), response.Data.Totals.CellsFailed)
	suite.Equal(int64(5), response.Data.Totals.RateLimitedTotal)

	var rateLimitCheck *AiDiagnosticsHealthCheck
	for i := range response.Data.Checks {
		if response.Data.Checks[i].ID == "rate_limit_pressure" {
			rateLimitCheck = &response.Data.Checks[i]
			break
		}
	}
	suite.Require().NotNil(rateLimitCheck)
	suite.Equal("warn", rateLimitCheck.Status)
	suite.NotEqual("No dashboard suggestion rate-limit snoozes were observed.", rateLimitCheck.Message)
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsRecentFailureRateUsesCellCompletedAt() {
	sspID := suite.seedDiagnosticsSSP("Recent Failure SSP")
	actorID := suite.dummyUserID()
	startedAt := time.Now().UTC().Add(-25 * time.Hour)
	completedAt := startedAt.Add(time.Minute)
	runID := suite.seedDiagnosticsRun(sspID, "failed", startedAt, &completedAt, actorID, 0, 0, 0, 0, 0)
	suite.seedDiagnosticsCell(runID, 0, "failed", 0, 0, 0, 0, 0, 0, 1)

	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[AiDiagnosticsSummary]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Equal("warn", diagnosticsCheckStatus(response.Data.Checks, "recent_failure_rate"))
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsRunsListFiltersCursorAndDetail() {
	sspA := suite.seedDiagnosticsSSP("Diagnostics A")
	sspB := suite.seedDiagnosticsSSP("Diagnostics B")
	actorID := suite.dummyUserID()
	base := time.Now().UTC().Add(-2 * time.Hour)
	oldCompletedAt := base.Add(1 * time.Minute)
	newCompletedAt := base.Add(61 * time.Minute)
	oldRun := suite.seedDiagnosticsRun(sspA, "completed", base, &oldCompletedAt, actorID, 10, 5, 4, 6, 0)
	newRun := suite.seedDiagnosticsRun(sspB, "failed", base.Add(time.Hour), &newCompletedAt, actorID, 20, 8, 2, 3, 1)
	suite.seedDiagnosticsCell(oldRun, 0, "completed", 10, 5, 4, 6, 0, 1, 0)
	suite.seedDiagnosticsCell(newRun, 0, "failed", 20, 8, 2, 3, 1, 0, 1)
	suite.seedDiagnosticsRunEvent(newRun, actorID)

	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/runs?limit=1", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var list struct {
		Data []AiDiagnosticsRun    `json:"data"`
		Meta aiDiagnosticsListMeta `json:"meta"`
	}
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	suite.Require().Len(list.Data, 1)
	suite.Equal(newRun.String(), list.Data[0].ID)
	suite.Equal("Diagnostics B", list.Data[0].SSPName)
	suite.Equal(1, list.Data[0].FailedCells)
	suite.Require().NotNil(list.Data[0].TriggeredBy)
	suite.Equal("Dummy User", list.Data[0].TriggeredBy.Name)
	suite.NotEmpty(list.Meta.NextCursor)

	rec, req = suite.req(http.MethodGet, "/api/admin/ai-diagnostics/runs?limit=1&cursor="+list.Meta.NextCursor, nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	suite.Require().Len(list.Data, 1)
	suite.Equal(oldRun.String(), list.Data[0].ID)

	rec, req = suite.req(http.MethodGet, "/api/admin/ai-diagnostics/runs?status=completed&sspId="+sspA.String(), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &list))
	suite.Require().Len(list.Data, 1)
	suite.Equal(oldRun.String(), list.Data[0].ID)

	rec, req = suite.req(http.MethodGet, "/api/admin/ai-diagnostics/runs/"+newRun.String(), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var detail apihandler.GenericDataResponse[AiDiagnosticsRunDetail]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &detail))
	suite.Equal(newRun.String(), detail.Data.ID)
	suite.Require().Len(detail.Data.Cells, 1)
	suite.Equal(1, detail.Data.Cells[0].RateLimitedCount)
	suite.Require().Len(detail.Data.Events, 1)
	suite.Require().NotNil(detail.Data.Events[0].Actor)
	suite.Equal("Dummy User", detail.Data.Events[0].Actor.Name)

	rec, req = suite.req(http.MethodGet, "/api/admin/ai-diagnostics/runs/"+uuid.New().String(), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)
}

func (suite *DashboardSuggestionsHTTPSuite) TestAiDiagnosticsAdminAuthAndFlagGate() {
	disabledServer := suite.newServer(false, suite.enqueuer, 0)
	rec, req := suite.req(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/admin/ai-diagnostics/summary", nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusUnauthorized, rec.Code)
}

func (suite *DashboardSuggestionsHTTPSuite) TestAcceptCreatesSSPFilterAndWritesEvents() {
	sspID, controlKeys, _ := suite.seedScope([]string{"AC-1", "AC-2"}, []map[string]string{{"env": "prod"}})
	runID := suite.seedSuggestionRun(sspID)
	catalogID, _ := suite.parseControlKey(controlKeys[0])
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	first := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "prod evidence", 0.9)
	second := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", labels, hash, "prod evidence", 0.7)

	body := dashboardSuggestionDecisionRequest{IDs: []uuid.UUID{*first.ID, *second.ID}}
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/accept", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var response apihandler.GenericDataResponse[acceptDashboardSuggestionsResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.Require().Len(response.Data.AcceptedFilterIDs, 1)
	filterID := response.Data.AcceptedFilterIDs[0]

	var filter relational.Filter
	suite.Require().NoError(suite.DB.First(&filter, "id = ? AND ssp_id = ?", filterID, sspID).Error)
	suite.Equal("prod evidence", filter.Name)

	var linkCount int64
	suite.Require().NoError(suite.DB.Table("filter_controls").Where("filter_id = ?", filterID).Count(&linkCount).Error)
	suite.Equal(int64(2), linkCount)

	var accepted []suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.Where("id IN ?", []uuid.UUID{*first.ID, *second.ID}).Find(&accepted).Error)
	for _, suggestion := range accepted {
		suite.Equal(suggestionrel.DashboardSuggestionStatusAccepted, suggestion.Status)
		suite.Require().NotNil(suggestion.AcceptedFilterID)
		suite.Equal(filterID, *suggestion.AcceptedFilterID)
	}

	var eventCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("event_type = ? AND suggestion_id IN ?", suggestionrel.DashboardSuggestionEventTypeAccepted, []uuid.UUID{*first.ID, *second.ID}).
		Count(&eventCount).Error)
	suite.Equal(int64(2), eventCount)
}

func (suite *DashboardSuggestionsHTTPSuite) TestEventsResolveActorDisplayDetails() {
	sspID, controlKeys, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})
	runID := suite.seedSuggestionRun(sspID)
	catalogID, _ := suite.parseControlKey(controlKeys[0])
	labels := map[string]string{"env": "prod"}
	hash := suggestionrel.CanonicalLabelSetHash(labels)
	suggestion := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", labels, hash, "prod evidence", 0.9)

	body := dashboardSuggestionDecisionRequest{IDs: []uuid.UUID{*suggestion.ID}}
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/accept", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	rec, req = suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/%s/events", sspID, suggestion.ID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Require().Equal(http.StatusOK, rec.Code, rec.Body.String())

	var eventsResponse apihandler.GenericDataListResponse[dashboardSuggestionEventResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &eventsResponse))

	var acceptedEvent *dashboardSuggestionEventResponse
	for i := range eventsResponse.Data {
		if eventsResponse.Data[i].EventType == string(suggestionrel.DashboardSuggestionEventTypeAccepted) {
			acceptedEvent = &eventsResponse.Data[i]
			break
		}
	}
	suite.Require().NotNil(acceptedEvent, "expected an accepted event")
	suite.Require().NotNil(acceptedEvent.ActorUserID, "accepted event should record the actor")
	suite.Require().NotNil(acceptedEvent.Actor, "accepted event should resolve actor details")
	suite.Equal(acceptedEvent.ActorUserID.String(), acceptedEvent.Actor.ID)
	suite.Equal("Dummy User", acceptedEvent.Actor.Name)
}

func (suite *DashboardSuggestionsHTTPSuite) TestRejectPersistsDecisionAndWritesEvents() {
	sspID, controlKeys, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})
	runID := suite.seedSuggestionRun(sspID)
	catalogID, _ := suite.parseControlKey(controlKeys[0])
	suggestion := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", map[string]string{"env": "prod"}, suggestionrel.CanonicalLabelSetHash(map[string]string{"env": "prod"}), "prod", 0.8)

	body := dashboardSuggestionDecisionRequest{IDs: []uuid.UUID{*suggestion.ID}, Reason: "not applicable"}
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/reject", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	var reloaded suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&reloaded, "id = ?", suggestion.ID).Error)
	suite.Equal(suggestionrel.DashboardSuggestionStatusRejected, reloaded.Status)
	suite.Require().NotNil(reloaded.RejectReason)
	suite.Equal("not applicable", *reloaded.RejectReason)
	suite.Require().NotNil(reloaded.DecidedByUserID)
	suite.Require().NotNil(reloaded.DecidedAt)

	var eventCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("suggestion_id = ? AND event_type = ?", suggestion.ID, suggestionrel.DashboardSuggestionEventTypeRejected).
		Count(&eventCount).Error)
	suite.Equal(int64(1), eventCount)
}

func (suite *DashboardSuggestionsHTTPSuite) TestPreviewAndGenerateApplyKebabLabelFilter() {
	sspID, _, _ := suite.seedScope(
		[]string{"AC-1"},
		[]map[string]string{{"env": "prod"}, {"env": "stage"}, {"env": "prod", "provider": "aws"}},
	)

	// Preview with no filter sees all 3 label sets.
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/preview", sspID), json.RawMessage(`{}`))
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var all apihandler.GenericDataResponse[dashboardSuggestionPreviewResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &all))
	suite.Equal(3, all.Data.LabelSetCount)

	// Preview with a kebab-case label-filter (as the UI sends) narrows to env=prod.
	body := json.RawMessage(`{"scope":{"label-filter":{"scope":{"condition":{"label":"env","operator":"=","value":"prod"}}}}}`)
	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/preview", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var filtered apihandler.GenericDataResponse[dashboardSuggestionPreviewResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &filtered))
	suite.Equal(2, filtered.Data.LabelSetCount)

	// Generate persists the filter on the run.
	rec, req = suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusAccepted, rec.Code, rec.Body.String())
	var run suggestionrel.DashboardSuggestionRun
	suite.Require().NoError(suite.DB.Where("ssp_id = ?", sspID).Order("started_at DESC").First(&run).Error)
	suite.Require().NotNil(suggestionrel.LabelFilterFromJSONMap(run.LabelFilter))
}

func (suite *DashboardSuggestionsHTTPSuite) TestEditGroupBindsKebabCaseBodyAndPersists() {
	sspID, controlKeys, _ := suite.seedScope([]string{"AC-1", "AC-2"}, []map[string]string{{"env": "prod"}})
	runID := suite.seedSuggestionRun(sspID)
	catalogID, _ := suite.parseControlKey(controlKeys[0])
	hash := suggestionrel.CanonicalLabelSetHash(map[string]string{"env": "prod"})
	ac1 := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", map[string]string{"env": "prod"}, hash, "AI name", 0.8)
	ac2 := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-2", map[string]string{"env": "prod"}, hash, "AI name", 0.7)

	// Send the body exactly as the UI does: kebab-case keys (decamelize-keys).
	body := json.RawMessage(fmt.Sprintf(`{
		"ids": [%q, %q],
		"proposed-filter-name": "Edited title",
		"proposed-filter-label-set": {"env": "prod", "team": "payments"},
		"add-control-keys": [%q],
		"remove-ids": [%q]
	}`, ac1.ID, ac2.ID, suggestionrel.ControlKey(catalogID, "AC-3"), ac2.ID))

	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/edit-group", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())

	// Kept row picks up the kebab-bound title + labels.
	var kept suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&kept, "id = ?", ac1.ID).Error)
	suite.True(kept.IsUserEdited)
	suite.Equal("Edited title", kept.ProposedFilterName)
	suite.Equal("payments", kept.ProposedFilterLabelSet["team"])
	suite.Equal("prod", kept.ProposedFilterLabelSet["env"])

	// Removed control was rejected; added control became a new pending row.
	var removed suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&removed, "id = ?", ac2.ID).Error)
	suite.Equal(suggestionrel.DashboardSuggestionStatusRejected, removed.Status)

	var added suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.First(&added, "ssp_id = ? AND control_id = ? AND status = ?", sspID, "AC-3", suggestionrel.DashboardSuggestionStatusPending).Error)
	suite.True(added.AddedByUser)
	suite.Equal("payments", added.ProposedFilterLabelSet["team"])
}

func (suite *DashboardSuggestionsHTTPSuite) TestListSuggestionsAndEventsScopeBySSP() {
	sspID, controlKeys, _ := suite.seedScope([]string{"AC-1"}, []map[string]string{{"env": "prod"}})
	otherSSPID, _, _ := suite.seedScope([]string{"AC-9"}, []map[string]string{{"env": "stage"}})
	runID := suite.seedSuggestionRun(sspID)
	otherRunID := suite.seedSuggestionRun(otherSSPID)
	catalogID, _ := suite.parseControlKey(controlKeys[0])
	suggestion := suite.seedDashboardSuggestion(runID, sspID, catalogID, "AC-1", map[string]string{"env": "prod"}, suggestionrel.CanonicalLabelSetHash(map[string]string{"env": "prod"}), "prod", 0.8)
	_ = suite.seedDashboardSuggestion(otherRunID, otherSSPID, catalogID, "AC-1", map[string]string{"env": "prod"}, suggestionrel.CanonicalLabelSetHash(map[string]string{"env": "prod"}), "hidden", 0.8)
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionEvent{
		RunID:        &runID,
		SuggestionID: suggestion.ID,
		EventType:    string(suggestionrel.DashboardSuggestionEventTypeSuggestionCreated),
		OccurredAt:   time.Now().UTC(),
		Payload:      datatypes.JSONMap{"source": "test"},
		Snapshot:     datatypes.JSONMap{},
	}).Error)

	rec, req := suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions", sspID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var listResponse apihandler.GenericDataListResponse[dashboardSuggestionResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &listResponse))
	suite.Require().Len(listResponse.Data, 1)
	suite.Equal(*suggestion.ID, *listResponse.Data[0].ID)
	suite.Equal("Control AC-1", listResponse.Data[0].ControlTitle)

	rec, req = suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/%s/events", sspID, suggestion.ID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code, rec.Body.String())
	var eventsResponse apihandler.GenericDataListResponse[dashboardSuggestionEventResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &eventsResponse))
	suite.Require().Len(eventsResponse.Data, 1)
	suite.Equal(string(suggestionrel.DashboardSuggestionEventTypeSuggestionCreated), eventsResponse.Data[0].EventType)
	// This event has no actor, so no actor details should be resolved.
	suite.Nil(eventsResponse.Data[0].Actor)

	rec, req = suite.req(http.MethodGet, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/%s/events", otherSSPID, suggestion.ID), nil)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusNotFound, rec.Code, rec.Body.String())
}

func (suite *DashboardSuggestionsHTTPSuite) TestGenerateSupersedesOnlyPendingSuggestionsInScope() {
	sspID, controlKeys, hashes := suite.seedScope([]string{"AC-1", "AC-2"}, []map[string]string{{"env": "prod"}, {"env": "stage"}})
	runID := suite.seedSuggestionRun(sspID)
	ac1CatalogID, _ := suite.parseControlKey(controlKeys[0])
	ac2CatalogID, _ := suite.parseControlKey(controlKeys[1])
	prodHash := hashes[0]
	stageHash := hashes[1]

	inScope := suite.seedDashboardSuggestion(runID, sspID, ac1CatalogID, "AC-1", map[string]string{"env": "prod"}, prodHash, "in scope", 0.9)
	outByControl := suite.seedDashboardSuggestion(runID, sspID, ac2CatalogID, "AC-2", map[string]string{"env": "prod"}, prodHash, "out control", 0.8)
	outByLabel := suite.seedDashboardSuggestion(runID, sspID, ac1CatalogID, "AC-1", map[string]string{"env": "stage"}, stageHash, "out label", 0.7)

	body := generateDashboardSuggestionsRequest{
		SupersedePending: true,
		Scope: &dashboardSuggestionScopeRequest{
			ControlKeys:    []string{controlKeys[0]},
			LabelSetHashes: []string{prodHash},
		},
	}
	rec, req := suite.req(http.MethodPost, fmt.Sprintf("/api/oscal/system-security-plans/%s/dashboard-suggestions/generate", sspID), body)
	suite.server.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusAccepted, rec.Code, rec.Body.String())

	statuses := map[uuid.UUID]string{}
	var suggestions []suggestionrel.DashboardSuggestion
	suite.Require().NoError(suite.DB.Where("id IN ?", []uuid.UUID{*inScope.ID, *outByControl.ID, *outByLabel.ID}).Find(&suggestions).Error)
	for _, suggestion := range suggestions {
		statuses[*suggestion.ID] = suggestion.Status
	}
	suite.Equal(suggestionrel.DashboardSuggestionStatusSuperseded, statuses[*inScope.ID])
	suite.Equal(suggestionrel.DashboardSuggestionStatusPending, statuses[*outByControl.ID])
	suite.Equal(suggestionrel.DashboardSuggestionStatusPending, statuses[*outByLabel.ID])

	var eventCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("suggestion_id = ? AND event_type = ?", inScope.ID, suggestionrel.DashboardSuggestionEventTypeSuperseded).
		Count(&eventCount).Error)
	suite.Equal(int64(1), eventCount)
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

func (suite *DashboardSuggestionsHTTPSuite) seedSuggestionRun(sspID uuid.UUID) uuid.UUID {
	runID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:     relational.UUIDModel{ID: &runID},
		SSPID:         sspID,
		Status:        "completed",
		Model:         "test-model",
		PromptVersion: suggestionrel.PromptVersion,
		Scope:         datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}},
		PlannedCalls:  1,
		Stats:         datatypes.JSONMap{},
	}).Error)
	return runID
}

func (suite *DashboardSuggestionsHTTPSuite) seedSuggestionRunStartedAt(sspID uuid.UUID, startedAt time.Time) uuid.UUID {
	runID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:     relational.UUIDModel{ID: &runID},
		SSPID:         sspID,
		Status:        "completed",
		Model:         "test-model",
		PromptVersion: suggestionrel.PromptVersion,
		Scope:         datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}},
		PlannedCalls:  1,
		StartedAt:     &startedAt,
		Stats:         datatypes.JSONMap{},
	}).Error)
	return runID
}

func (suite *DashboardSuggestionsHTTPSuite) seedControlResult(runID uuid.UUID, sspID uuid.UUID, catalogID uuid.UUID, controlID string, outcome string, suggestionCount int, evaluatedAt time.Time) {
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionControlResult{
		RunID:            runID,
		SSPID:            sspID,
		ControlCatalogID: catalogID,
		ControlID:        controlID,
		Outcome:          outcome,
		SuggestionCount:  suggestionCount,
		EvaluatedAt:      &evaluatedAt,
	}).Error)
}

func (suite *DashboardSuggestionsHTTPSuite) seedDiagnosticsSSP(title string) uuid.UUID {
	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	parentID := sspID.String()
	parentType := "system_security_plans"
	suite.Require().NoError(suite.DB.Create(&relational.Metadata{
		ParentID:   &parentID,
		ParentType: &parentType,
		Title:      title,
	}).Error)
	return sspID
}

func (suite *DashboardSuggestionsHTTPSuite) seedDiagnosticsRun(
	sspID uuid.UUID,
	status string,
	startedAt time.Time,
	completedAt *time.Time,
	actorID uuid.UUID,
	inputTokens int,
	outputTokens int,
	cacheReadInputTokens int,
	cacheCreationInputTokens int,
	rateLimitedCount int,
) uuid.UUID {
	runID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:                relational.UUIDModel{ID: &runID},
		SSPID:                    sspID,
		Status:                   status,
		Model:                    "test-model",
		PromptVersion:            suggestionrel.PromptVersion,
		Scope:                    datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}},
		PlannedCalls:             1,
		TriggeredByUserID:        &actorID,
		StartedAt:                &startedAt,
		CompletedAt:              completedAt,
		InputTokens:              inputTokens,
		OutputTokens:             outputTokens,
		CacheReadInputTokens:     cacheReadInputTokens,
		CacheCreationInputTokens: cacheCreationInputTokens,
		RateLimitedCount:         rateLimitedCount,
		Stats:                    datatypes.JSONMap{},
	}).Error)
	return runID
}

func (suite *DashboardSuggestionsHTTPSuite) seedDiagnosticsCell(
	runID uuid.UUID,
	cellIndex int,
	status string,
	inputTokens int,
	outputTokens int,
	cacheReadInputTokens int,
	cacheCreationInputTokens int,
	rateLimitedCount int,
	mappingsReturned int,
	mappingsRejected int,
) {
	completedAt := time.Now().UTC()
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRunCell{
		RunID:                    runID,
		CellIndex:                cellIndex,
		ControlKeys:              datatypes.NewJSONSlice([]string{"catalog:AC-1"}),
		LabelSetHashes:           datatypes.NewJSONSlice([]string{"hash"}),
		Status:                   status,
		InputTokens:              inputTokens,
		OutputTokens:             outputTokens,
		CacheReadInputTokens:     cacheReadInputTokens,
		CacheCreationInputTokens: cacheCreationInputTokens,
		RateLimitedCount:         rateLimitedCount,
		MappingsReturned:         mappingsReturned,
		MappingsRejected:         mappingsRejected,
		CompletedAt:              &completedAt,
	}).Error)
}

func (suite *DashboardSuggestionsHTTPSuite) seedDiagnosticsSuggestion(runID uuid.UUID, sspID uuid.UUID, status string) {
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestion{
		RunID:              runID,
		SSPID:              sspID,
		ControlCatalogID:   uuid.New(),
		ControlID:          "AC-1",
		LabelSet:           datatypes.JSONMap{"env": "prod"},
		LabelSetHash:       suggestionrel.CanonicalLabelSetHash(map[string]string{"env": "prod"}),
		ProposedFilterName: "diagnostic filter",
		Reasoning:          "diagnostic reasoning",
		Confidence:         0.9,
		Status:             status,
	}).Error)
}

func (suite *DashboardSuggestionsHTTPSuite) seedDiagnosticsRunEvent(runID uuid.UUID, actorID uuid.UUID) {
	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionEvent{
		RunID:       &runID,
		EventType:   string(suggestionrel.DashboardSuggestionEventTypeRunCompleted),
		ActorUserID: &actorID,
		OccurredAt:  time.Now().UTC(),
		Payload:     datatypes.JSONMap{},
		Snapshot:    datatypes.JSONMap{},
	}).Error)
}

func ptrTime(v time.Time) *time.Time {
	return &v
}

func (suite *DashboardSuggestionsHTTPSuite) dummyUserID() uuid.UUID {
	var user relational.User
	suite.Require().NoError(suite.DB.Where("email = ?", "dummy@example.com").First(&user).Error)
	suite.Require().NotNil(user.ID)
	return *user.ID
}

func diagnosticsCheckStatus(checks []AiDiagnosticsHealthCheck, id string) string {
	for _, check := range checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}

func (suite *DashboardSuggestionsHTTPSuite) seedDashboardSuggestion(
	runID uuid.UUID,
	sspID uuid.UUID,
	catalogID uuid.UUID,
	controlID string,
	labels map[string]string,
	hash string,
	name string,
	confidence float64,
) suggestionrel.DashboardSuggestion {
	suggestion := suggestionrel.DashboardSuggestion{
		RunID:              runID,
		SSPID:              sspID,
		ControlCatalogID:   catalogID,
		ControlID:          controlID,
		LabelSet:           datatypes.JSONMap{},
		LabelSetHash:       hash,
		ProposedFilterName: name,
		Reasoning:          "test reasoning",
		Confidence:         confidence,
		Status:             suggestionrel.DashboardSuggestionStatusPending,
	}
	for key, value := range labels {
		suggestion.LabelSet[key] = value
	}
	suite.Require().NoError(suite.DB.Create(&suggestion).Error)
	return suggestion
}

func (suite *DashboardSuggestionsHTTPSuite) parseControlKey(key string) (uuid.UUID, string) {
	catalogID, controlID, err := suggestionrel.ParseControlKey(key)
	suite.Require().NoError(err)
	return catalogID, controlID
}
