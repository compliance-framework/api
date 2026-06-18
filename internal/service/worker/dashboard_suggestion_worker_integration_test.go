//go:build integration

package worker

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/llm"
	"github.com/compliance-framework/api/internal/service/relational"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"gorm.io/datatypes"
)

type DashboardSuggestionWorkerIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func TestDashboardSuggestionWorkerIntegrationSuite(t *testing.T) {
	suite.Run(t, new(DashboardSuggestionWorkerIntegrationSuite))
}

func (suite *DashboardSuggestionWorkerIntegrationSuite) SetupTest() {
	suite.Require().NoError(suite.Migrator.Refresh())
}

func (suite *DashboardSuggestionWorkerIntegrationSuite) TestTwoByTwoGridConcurrentShuffledFinalizesAndRerunDoesNotDuplicate() {
	ctx := context.Background()
	runID, cells := suite.seedTwoByTwoSuggestionRun()
	client := &promptMappingClient{}
	worker := NewDashboardSuggestionWorker(suite.DB, client, &config.AIConfig{RequestTimeout: 120 * time.Second, MaxSuggestionsPerRun: 10}, zap.NewNop().Sugar())

	order := []int{2, 0, 3, 1}
	var wg sync.WaitGroup
	errs := make(chan error, len(order))
	for _, cellIndex := range order {
		wg.Add(1)
		go func(cellIndex int) {
			defer wg.Done()
			errs <- worker.Work(ctx, dashboardSuggestionIntegrationJob(runID, cellIndex))
		}(cellIndex)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		suite.Require().NoError(err)
	}

	var run suggestionrel.DashboardSuggestionRun
	suite.Require().NoError(suite.DB.First(&run, "id = ?", runID).Error)
	suite.Equal(dashboardSuggestionRunStatusCompleted, run.Status)
	suite.Equal(4, run.SuggestionCount)
	suite.Equal(40, run.InputTokens)
	suite.Equal(20, run.OutputTokens)
	suite.NotNil(run.StartedAt)
	suite.NotNil(run.CompletedAt)

	for _, cell := range cells {
		var stored suggestionrel.DashboardSuggestionRunCell
		suite.Require().NoError(suite.DB.First(&stored, "run_id = ? AND cell_index = ?", runID, cell.CellIndex).Error)
		suite.Equal(dashboardSuggestionCellStatusCompleted, stored.Status)
		suite.Equal(10, stored.InputTokens)
		suite.Equal(5, stored.OutputTokens)
		suite.Equal(1, stored.MappingsReturned)
		suite.Equal(0, stored.MappingsRejected)
	}

	var suggestionCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestion{}).Where("run_id = ?", runID).Count(&suggestionCount).Error)
	suite.Equal(int64(4), suggestionCount)
	var completedEvents int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("run_id = ? AND event_type = ?", runID, suggestionrel.DashboardSuggestionEventTypeRunCompleted).
		Count(&completedEvents).Error)
	suite.Equal(int64(1), completedEvents)

	for _, cell := range cells {
		suite.Require().NoError(worker.Work(ctx, dashboardSuggestionIntegrationJob(runID, cell.CellIndex)))
	}
	var afterRerunCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestion{}).Where("run_id = ?", runID).Count(&afterRerunCount).Error)
	suite.Equal(suggestionCount, afterRerunCount)
}

func (suite *DashboardSuggestionWorkerIntegrationSuite) TestRateLimitSnoozesCellWithoutFailing() {
	ctx := context.Background()
	runID, cells := suite.seedTwoByTwoSuggestionRun()
	client := &llm.FakeClient{Err: &llm.RateLimitError{RetryAfter: 5 * time.Second}}
	worker := NewDashboardSuggestionWorker(suite.DB, client, &config.AIConfig{RequestTimeout: 120 * time.Second, MaxSuggestionsPerRun: 10}, zap.NewNop().Sugar())

	err := worker.Work(ctx, dashboardSuggestionIntegrationJob(runID, cells[0].CellIndex))

	// The cell is snoozed (not failed) and the run is not finalized as failed.
	var snooze *rivertype.JobSnoozeError
	suite.Require().ErrorAs(err, &snooze)
	suite.Require().GreaterOrEqual(snooze.Duration, 5*time.Second)

	var cell suggestionrel.DashboardSuggestionRunCell
	suite.Require().NoError(suite.DB.First(&cell, "run_id = ? AND cell_index = ?", runID, cells[0].CellIndex).Error)
	suite.Require().Equal(dashboardSuggestionCellStatusPending, cell.Status)

	var run suggestionrel.DashboardSuggestionRun
	suite.Require().NoError(suite.DB.First(&run, "id = ?", runID).Error)
	suite.Require().NotEqual(dashboardSuggestionRunStatusFailed, run.Status)
}

func (suite *DashboardSuggestionWorkerIntegrationSuite) TestEmptyOutputCompletesCellWithoutSuggestions() {
	ctx := context.Background()
	runID, cells := suite.seedTwoByTwoSuggestionRun()
	// The model declines to emit structured output for every cell.
	client := &llm.FakeClient{Responses: []*llm.StructuredResponse{
		{EmptyOutput: true, Model: "fake-model", InputTokens: 10, OutputTokens: 5},
		{EmptyOutput: true, Model: "fake-model", InputTokens: 10, OutputTokens: 5},
		{EmptyOutput: true, Model: "fake-model", InputTokens: 10, OutputTokens: 5},
		{EmptyOutput: true, Model: "fake-model", InputTokens: 10, OutputTokens: 5},
	}}
	worker := NewDashboardSuggestionWorker(suite.DB, client, &config.AIConfig{RequestTimeout: 120 * time.Second, MaxSuggestionsPerRun: 10}, zap.NewNop().Sugar())

	for _, cell := range cells {
		suite.Require().NoError(worker.Work(ctx, dashboardSuggestionIntegrationJob(runID, cell.CellIndex)))
	}

	// Every cell is completed (not failed) with zero mappings returned.
	for _, cell := range cells {
		var stored suggestionrel.DashboardSuggestionRunCell
		suite.Require().NoError(suite.DB.First(&stored, "run_id = ? AND cell_index = ?", runID, cell.CellIndex).Error)
		suite.Equal(dashboardSuggestionCellStatusCompleted, stored.Status)
		suite.Equal(0, stored.MappingsReturned)
		suite.Nil(stored.Error)
	}

	// The run finalizes as completed with no suggestions.
	var run suggestionrel.DashboardSuggestionRun
	suite.Require().NoError(suite.DB.First(&run, "id = ?", runID).Error)
	suite.Equal(dashboardSuggestionRunStatusCompleted, run.Status)
	suite.Equal(0, run.SuggestionCount)

	var suggestionCount int64
	suite.Require().NoError(suite.DB.Model(&suggestionrel.DashboardSuggestion{}).Where("run_id = ?", runID).Count(&suggestionCount).Error)
	suite.Equal(int64(0), suggestionCount)
}

func (suite *DashboardSuggestionWorkerIntegrationSuite) seedTwoByTwoSuggestionRun() (uuid.UUID, []suggestionrel.GridCell) {
	sspID := uuid.New()
	runID := uuid.New()
	catalogID := uuid.New()
	profileID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.Profile{UUIDModel: relational.UUIDModel{ID: &profileID}}).Error)
	suite.Require().NoError(suite.DB.Exec(`INSERT INTO ssp_profiles (system_security_plan_id, profile_id) VALUES (?, ?)`, sspID, profileID).Error)

	controlIDs := []string{"AC-1", "AC-2"}
	controlKeys := make([]string, 0, len(controlIDs))
	implementationID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.ControlImplementation{
		UUIDModel:            relational.UUIDModel{ID: &implementationID},
		SystemSecurityPlanId: sspID,
	}).Error)
	for _, controlID := range controlIDs {
		controlKeys = append(controlKeys, suggestionrel.ControlKey(catalogID, controlID))
		suite.Require().NoError(suite.DB.Create(&relational.Control{
			CatalogID: catalogID,
			ID:        controlID,
			Title:     controlID + " title",
			Parts:     datatypes.NewJSONSlice([]relational.Part{}),
		}).Error)
		suite.Require().NoError(suite.DB.Exec(`INSERT INTO profile_controls (profile_id, control_catalog_id, control_id) VALUES (?, ?, ?)`, profileID, catalogID, controlID).Error)
		implementedRequirementID := uuid.New()
		suite.Require().NoError(suite.DB.Create(&relational.ImplementedRequirement{
			UUIDModel:               relational.UUIDModel{ID: &implementedRequirementID},
			ControlImplementationId: implementationID,
			ControlId:               controlID,
			Remarks:                 controlID + " implementation",
		}).Error)
	}

	labelSets := []map[string]string{
		{"env": "prod", "service": "api"},
		{"env": "stage", "service": "worker"},
	}
	labelSetHashes := make([]string, 0, len(labelSets))
	for i, labels := range labelSets {
		hash := suggestionrel.CanonicalLabelSetHash(labels)
		labelSetHashes = append(labelSetHashes, hash)
		evidenceID := uuid.New()
		streamID := uuid.New()
		suite.Require().NoError(suite.DB.Exec(
			`INSERT INTO evidences (id, uuid, title, description, start, "end") VALUES (?, ?, ?, ?, ?, ?)`,
			evidenceID,
			streamID,
			"evidence",
			"evidence",
			time.Now().UTC().Add(time.Duration(i)*time.Minute),
			time.Now().UTC().Add(time.Duration(i)*time.Minute),
		).Error)
		for key, value := range labels {
			suite.Require().NoError(suite.DB.Exec(`INSERT INTO evidence_labels (evidence_id, labels_name, labels_value) VALUES (?, ?, ?)`, evidenceID, key, value).Error)
		}
	}

	suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:       relational.UUIDModel{ID: &runID},
		SSPID:           sspID,
		Status:          dashboardSuggestionRunStatusPending,
		Model:           "fake-model",
		PromptVersion:   suggestionrel.PromptVersion,
		Scope:           datatypes.JSONMap{"controlKeys": controlKeys, "labelSetHashes": labelSetHashes},
		PlannedCalls:    4,
		SuggestionCount: 0,
		Stats:           datatypes.JSONMap{},
	}).Error)

	cells := suggestionrel.BuildGrid(suggestionrel.Snapshot{ControlKeys: controlKeys, LabelSetHashes: labelSetHashes}, suggestionrel.ChunkConfig{
		MaxControlsPerChunk:  1,
		MaxLabelSetsPerChunk: 1,
	})
	for _, cell := range cells {
		suite.Require().NoError(suite.DB.Create(&suggestionrel.DashboardSuggestionRunCell{
			RunID:          runID,
			CellIndex:      cell.CellIndex,
			ControlKeys:    datatypes.NewJSONSlice(cell.ControlKeys),
			LabelSetHashes: datatypes.NewJSONSlice(cell.LabelSetHashes),
			Status:         dashboardSuggestionCellStatusPending,
		}).Error)
	}
	return runID, cells
}

type promptMappingClient struct {
	mu       sync.Mutex
	requests int
}

func (c *promptMappingClient) CompleteStructured(ctx context.Context, req llm.StructuredRequest) (*llm.StructuredResponse, error) {
	c.mu.Lock()
	c.requests++
	c.mu.Unlock()

	// Controls and label-sets are split across cache segments now, so search the
	// whole rendered request rather than just the volatile tail.
	combined := req.System + "\n" + req.CachedUserPrefix + "\n" + req.Prompt
	controlKey := firstPromptValue(combined, `"control_key": "([^"]+)"`)
	labelSetHash := firstPromptValue(combined, `"hash": "([^"]+)"`)
	raw, err := json.Marshal(suggestionrel.RawMappings{Mappings: []suggestionrel.RawMapping{
		{
			ControlKey:         controlKey,
			LabelSetHash:       labelSetHash,
			Action:             suggestionrel.MappingActionNewFilter,
			ProposedFilterName: "Dashboard " + labelSetHash[:8],
			Confidence:         0.9,
			Reasoning:          "Evidence satisfies the control and belongs to this system.",
		},
	}})
	if err != nil {
		return nil, err
	}
	return &llm.StructuredResponse{
		Raw:          raw,
		Model:        "fake-model",
		InputTokens:  10,
		OutputTokens: 5,
	}, nil
}

func firstPromptValue(prompt string, pattern string) string {
	match := regexp.MustCompile(pattern).FindStringSubmatch(prompt)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func dashboardSuggestionIntegrationJob(runID uuid.UUID, cellIndex int) *river.Job[DashboardSuggestionCellArgs] {
	return &river.Job[DashboardSuggestionCellArgs]{
		JobRow: &rivertype.JobRow{
			ID:          int64(cellIndex + 1),
			Attempt:     1,
			MaxAttempts: 3,
		},
		Args: DashboardSuggestionCellArgs{RunID: runID, CellIndex: cellIndex},
	}
}
