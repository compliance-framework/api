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

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/dashboard-suggestions/config", nil)
	disabledServer.E().ServeHTTP(rec, req)
	suite.Equal(http.StatusOK, rec.Code)
	var response apihandler.GenericDataResponse[dashboardSuggestionConfigResponse]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &response))
	suite.False(response.Data.Enabled)
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
	var eventsResponse apihandler.GenericDataListResponse[suggestionrel.DashboardSuggestionEvent]
	suite.Require().NoError(json.Unmarshal(rec.Body.Bytes(), &eventsResponse))
	suite.Require().Len(eventsResponse.Data, 1)
	suite.Equal(string(suggestionrel.DashboardSuggestionEventTypeSuggestionCreated), eventsResponse.Data[0].EventType)

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
