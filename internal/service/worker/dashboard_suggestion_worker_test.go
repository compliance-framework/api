package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/llm"
	"github.com/compliance-framework/api/internal/service/relational"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestDashboardSuggestionCellJobType(t *testing.T) {
	t.Parallel()

	args := DashboardSuggestionCellArgs{RunID: uuid.New(), CellIndex: 4}
	require.Equal(t, JobTypeDashboardSuggestionCell, args.Kind())
	require.Equal(t, 5*time.Minute, args.Timeout())

	opts := JobInsertOptionsForDashboardSuggestionCell()
	require.Equal(t, DashboardSuggestionQueue, opts.Queue)
	require.Equal(t, 3, opts.MaxAttempts)
	require.True(t, opts.UniqueOpts.ByArgs)
}

func TestBuildRiverConfigSuggestionQueueGated(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultWorkerConfig()
	withoutAI := buildRiverConfig(cfg, river.NewWorkers(), nil)
	_, ok := withoutAI.Queues[DashboardSuggestionQueue]
	require.False(t, ok)

	withAI := buildRiverConfig(cfg, river.NewWorkers(), nil, &config.AIConfig{Enabled: true, QueueWorkers: 9})
	queue, ok := withAI.Queues[DashboardSuggestionQueue]
	require.True(t, ok)
	require.Equal(t, 9, queue.MaxWorkers)
}

func TestServiceEnqueueDashboardSuggestionCellsDisabled(t *testing.T) {
	t.Parallel()

	svc := &Service{config: config.DefaultWorkerConfig(), aiEnabled: false}
	err := svc.EnqueueDashboardSuggestionCells(context.Background(), uuid.New(), 2)
	require.ErrorIs(t, err, ErrDashboardSuggestionWorkerDisabled)
}

func TestDashboardSuggestionWorkerNonPendingCellNoops(t *testing.T) {
	db := newDashboardSuggestionWorkerTestDB(t)
	runID, sspID := seedDashboardSuggestionRun(t, db, dashboardSuggestionRunStatusRunning, 1)
	seedDashboardSuggestionCell(t, db, runID, 0, dashboardSuggestionCellStatusCompleted)
	fake := &llm.FakeClient{Raw: json.RawMessage(`{"mappings":[]}`)}
	worker := NewDashboardSuggestionWorker(db, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

	err := worker.Work(context.Background(), dashboardSuggestionJob(runID, 0, 1, 3))
	require.NoError(t, err)
	require.Empty(t, fake.Requests)

	var eventCount int64
	require.NoError(t, db.Model(&suggestionrel.DashboardSuggestionEvent{}).Where("run_id = ?", runID).Count(&eventCount).Error)
	require.Zero(t, eventCount)

	var run suggestionrel.DashboardSuggestionRun
	require.NoError(t, db.First(&run, "id = ? AND ssp_id = ?", runID, sspID).Error)
	require.Equal(t, dashboardSuggestionRunStatusRunning, run.Status)
}

func TestDashboardSuggestionWorkerRunStartedEmittedOnce(t *testing.T) {
	db := newDashboardSuggestionWorkerTestDB(t)
	runID, _ := seedDashboardSuggestionRun(t, db, dashboardSuggestionRunStatusPending, 3)
	for i := range 3 {
		seedDashboardSuggestionCell(t, db, runID, i, dashboardSuggestionCellStatusPending)
	}
	worker := NewDashboardSuggestionWorker(db, &llm.FakeClient{}, config.DefaultAIConfig(), zap.NewNop().Sugar())

	for i := range 3 {
		_, _, ok, err := worker.loadPendingCellAndStartRun(context.Background(), DashboardSuggestionCellArgs{RunID: runID, CellIndex: i})
		require.NoError(t, err)
		require.True(t, ok)
	}

	var eventCount int64
	require.NoError(t, db.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("run_id = ? AND event_type = ?", runID, suggestionrel.DashboardSuggestionEventTypeRunStarted).
		Count(&eventCount).Error)
	require.Equal(t, int64(1), eventCount)

	var run suggestionrel.DashboardSuggestionRun
	require.NoError(t, db.First(&run, "id = ?", runID).Error)
	require.Equal(t, dashboardSuggestionRunStatusRunning, run.Status)
	require.NotNil(t, run.StartedAt)
}

func TestDashboardSuggestionWorkerFinalizationMatrix(t *testing.T) {
	t.Run("mixed success failure completes run", func(t *testing.T) {
		db := newDashboardSuggestionWorkerTestDB(t)
		runID, _ := seedDashboardSuggestionRun(t, db, dashboardSuggestionRunStatusRunning, 2)
		seedDashboardSuggestionCellWithStats(t, db, runID, 0, dashboardSuggestionCellStatusCompleted, 11, 7, 2, 1, nil)
		seedDashboardSuggestionCell(t, db, runID, 1, dashboardSuggestionCellStatusPending)
		worker := NewDashboardSuggestionWorker(db, &llm.FakeClient{}, config.DefaultAIConfig(), zap.NewNop().Sugar())

		require.NoError(t, worker.failCellAndMaybeFinalize(context.Background(), DashboardSuggestionCellArgs{RunID: runID, CellIndex: 1}, errors.New("provider failed")))

		var run suggestionrel.DashboardSuggestionRun
		require.NoError(t, db.First(&run, "id = ?", runID).Error)
		require.Equal(t, dashboardSuggestionRunStatusCompleted, run.Status)
		require.Equal(t, 11, run.InputTokens)
		require.Equal(t, 7, run.OutputTokens)
		require.Equal(t, "1", fmt.Sprint(run.Stats["cells_completed"]))
		require.Equal(t, "1", fmt.Sprint(run.Stats["cells_failed"]))
		require.NotNil(t, run.CompletedAt)
		assertRunEventCount(t, db, runID, suggestionrel.DashboardSuggestionEventTypeRunCompleted, 1)
	})

	t.Run("all failed fails run", func(t *testing.T) {
		db := newDashboardSuggestionWorkerTestDB(t)
		runID, _ := seedDashboardSuggestionRun(t, db, dashboardSuggestionRunStatusRunning, 2)
		seedDashboardSuggestionCellWithStats(t, db, runID, 0, dashboardSuggestionCellStatusFailed, 0, 0, 0, 0, ptrString("already failed"))
		seedDashboardSuggestionCell(t, db, runID, 1, dashboardSuggestionCellStatusPending)
		worker := NewDashboardSuggestionWorker(db, &llm.FakeClient{}, config.DefaultAIConfig(), zap.NewNop().Sugar())

		require.NoError(t, worker.failCellAndMaybeFinalize(context.Background(), DashboardSuggestionCellArgs{RunID: runID, CellIndex: 1}, errors.New("auth failed")))

		var run suggestionrel.DashboardSuggestionRun
		require.NoError(t, db.First(&run, "id = ?", runID).Error)
		require.Equal(t, dashboardSuggestionRunStatusFailed, run.Status)
		require.NotNil(t, run.CompletedAt)
		assertRunEventCount(t, db, runID, suggestionrel.DashboardSuggestionEventTypeRunFailed, 1)
	})
}

func TestDashboardSuggestionWorkerLLMRetryAndNonRetryableFailure(t *testing.T) {
	t.Run("retryable error retries once in job", func(t *testing.T) {
		fake := &llm.FakeClient{
			Errors: []error{llm.ErrRateLimited},
			Responses: []*llm.StructuredResponse{
				nil,
				{Raw: json.RawMessage(`{"mappings":[]}`), Model: "fake", InputTokens: 3, OutputTokens: 5},
			},
		}
		worker := NewDashboardSuggestionWorker(nil, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

		response, err := worker.completeWithOneRetry(context.Background(), "prompt")
		require.NoError(t, err)
		require.Equal(t, 3, response.InputTokens)
		require.Equal(t, 5, response.OutputTokens)
		require.Len(t, fake.Requests, 2)
	})

	t.Run("non retryable error fails cell immediately", func(t *testing.T) {
		fake := &llm.FakeClient{Err: llm.ErrAuth}
		worker := NewDashboardSuggestionWorker(nil, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

		_, err := worker.completeWithOneRetry(context.Background(), "prompt")
		require.ErrorIs(t, err, llm.ErrAuth)
		require.True(t, isNonRetryableLLMError(err))
		require.Len(t, fake.Requests, 1)
	})
}

func newDashboardSuggestionWorkerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.SystemSecurityPlan{},
		&relational.SystemCharacteristics{},
		&relational.SystemImplementation{},
		&relational.SystemComponent{},
		&relational.Control{},
		&relational.Filter{},
		&suggestionrel.DashboardSuggestionRun{},
		&suggestionrel.DashboardSuggestionRunCell{},
		&suggestionrel.DashboardSuggestion{},
		&suggestionrel.DashboardSuggestionEvent{},
	))
	return db
}

func seedDashboardSuggestionRun(t *testing.T, db *gorm.DB, status string, plannedCalls int) (uuid.UUID, uuid.UUID) {
	t.Helper()
	runID := uuid.New()
	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)
	require.NoError(t, db.Create(&suggestionrel.DashboardSuggestionRun{
		UUIDModel:       relational.UUIDModel{ID: &runID},
		SSPID:           sspID,
		Status:          status,
		Model:           "fake-model",
		PromptVersion:   suggestionrel.PromptVersion,
		Scope:           datatypes.JSONMap{"controlKeys": []string{}, "labelSetHashes": []string{}},
		PlannedCalls:    plannedCalls,
		SuggestionCount: 0,
		Stats:           datatypes.JSONMap{},
	}).Error)
	return runID, sspID
}

func seedDashboardSuggestionCell(t *testing.T, db *gorm.DB, runID uuid.UUID, cellIndex int, status string) {
	t.Helper()
	seedDashboardSuggestionCellWithStats(t, db, runID, cellIndex, status, 0, 0, 0, 0, nil)
}

func seedDashboardSuggestionCellWithStats(t *testing.T, db *gorm.DB, runID uuid.UUID, cellIndex int, status string, inputTokens int, outputTokens int, mappingsReturned int, mappingsRejected int, message *string) {
	t.Helper()
	completedAt := time.Now().UTC()
	require.NoError(t, db.Create(&suggestionrel.DashboardSuggestionRunCell{
		RunID:            runID,
		CellIndex:        cellIndex,
		ControlKeys:      datatypes.NewJSONSlice([]string{}),
		LabelSetHashes:   datatypes.NewJSONSlice([]string{}),
		Status:           status,
		Error:            message,
		InputTokens:      inputTokens,
		OutputTokens:     outputTokens,
		MappingsReturned: mappingsReturned,
		MappingsRejected: mappingsRejected,
		CompletedAt:      &completedAt,
	}).Error)
}

func dashboardSuggestionJob(runID uuid.UUID, cellIndex int, attempt int, maxAttempts int) *river.Job[DashboardSuggestionCellArgs] {
	return &river.Job[DashboardSuggestionCellArgs]{
		JobRow: &rivertype.JobRow{
			ID:          1,
			Attempt:     attempt,
			MaxAttempts: maxAttempts,
		},
		Args: DashboardSuggestionCellArgs{RunID: runID, CellIndex: cellIndex},
	}
}

func assertRunEventCount(t *testing.T, db *gorm.DB, runID uuid.UUID, eventType suggestionrel.DashboardSuggestionEventType, expected int64) {
	t.Helper()
	var count int64
	require.NoError(t, db.Model(&suggestionrel.DashboardSuggestionEvent{}).
		Where("run_id = ? AND event_type = ?", runID, eventType).
		Count(&count).Error)
	require.Equal(t, expected, count)
}

func ptrString(value string) *string {
	return &value
}
