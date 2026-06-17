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
	require.Equal(t, DashboardSuggestionMaxAttempts, opts.MaxAttempts)
	require.True(t, opts.UniqueOpts.ByArgs)
}

func TestDashboardSuggestionWorkerTimeout(t *testing.T) {
	t.Parallel()

	worker := NewDashboardSuggestionWorker(nil, nil, config.DefaultAIConfig(), zap.NewNop().Sugar())
	require.Equal(t, 5*time.Minute, worker.Timeout(nil))

	worker = NewDashboardSuggestionWorker(nil, nil, &config.AIConfig{RequestTimeout: 3 * time.Minute}, zap.NewNop().Sugar())
	require.Equal(t, 6*time.Minute+30*time.Second, worker.Timeout(nil))

	worker = NewDashboardSuggestionWorker(nil, nil, &config.AIConfig{}, zap.NewNop().Sugar())
	require.Equal(t, 5*time.Minute, worker.Timeout(nil))
}

func TestBuildRiverConfigSuggestionQueueGated(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultWorkerConfig()
	withoutAI := buildRiverConfig(cfg, river.NewWorkers(), nil, nil)
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
		require.NoError(t, db.Model(&suggestionrel.DashboardSuggestionRunCell{}).
			Where("run_id = ? AND cell_index = ?", runID, 0).
			Updates(map[string]any{
				"cache_read_input_tokens":     13,
				"cache_creation_input_tokens": 17,
				"rate_limited_count":          2,
			}).Error)
		seedDashboardSuggestionCell(t, db, runID, 1, dashboardSuggestionCellStatusPending)
		worker := NewDashboardSuggestionWorker(db, &llm.FakeClient{}, config.DefaultAIConfig(), zap.NewNop().Sugar())

		require.NoError(t, worker.failCellAndMaybeFinalize(context.Background(), DashboardSuggestionCellArgs{RunID: runID, CellIndex: 1}, errors.New("provider failed")))

		var run suggestionrel.DashboardSuggestionRun
		require.NoError(t, db.First(&run, "id = ?", runID).Error)
		require.Equal(t, dashboardSuggestionRunStatusCompleted, run.Status)
		require.Equal(t, 11, run.InputTokens)
		require.Equal(t, 7, run.OutputTokens)
		require.Equal(t, 13, run.CacheReadInputTokens)
		require.Equal(t, 17, run.CacheCreationInputTokens)
		require.Equal(t, 2, run.RateLimitedCount)
		require.Equal(t, "1", fmt.Sprint(run.Stats["cells_completed"]))
		require.Equal(t, "1", fmt.Sprint(run.Stats["cells_failed"]))
		require.Equal(t, "13", fmt.Sprint(run.Stats["cache_read_input_tokens"]))
		require.Equal(t, "17", fmt.Sprint(run.Stats["cache_creation_input_tokens"]))
		require.Equal(t, "1", fmt.Sprint(run.Stats["rate_limited_cells"]))
		require.Equal(t, "2", fmt.Sprint(run.Stats["rate_limited_total"]))
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

func TestDashboardSuggestionWorkerFailCellDetachedFromCancelledContext(t *testing.T) {
	db := newDashboardSuggestionWorkerTestDB(t)
	runID, _ := seedDashboardSuggestionRun(t, db, dashboardSuggestionRunStatusRunning, 1)
	seedDashboardSuggestionCell(t, db, runID, 0, dashboardSuggestionCellStatusPending)
	worker := NewDashboardSuggestionWorker(db, &llm.FakeClient{}, config.DefaultAIConfig(), zap.NewNop().Sugar())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.NoError(t, worker.failCellAndMaybeFinalize(ctx, DashboardSuggestionCellArgs{RunID: runID, CellIndex: 0}, errors.New("provider failed")))

	var cell suggestionrel.DashboardSuggestionRunCell
	require.NoError(t, db.First(&cell, "run_id = ? AND cell_index = ?", runID, 0).Error)
	require.Equal(t, dashboardSuggestionCellStatusFailed, cell.Status)
	require.NotNil(t, cell.CompletedAt)
	require.NotNil(t, cell.Error)
	require.Equal(t, "provider failed", *cell.Error)

	var run suggestionrel.DashboardSuggestionRun
	require.NoError(t, db.First(&run, "id = ?", runID).Error)
	require.Equal(t, dashboardSuggestionRunStatusFailed, run.Status)
	require.NotNil(t, run.CompletedAt)
	assertRunEventCount(t, db, runID, suggestionrel.DashboardSuggestionEventTypeRunFailed, 1)
}

func TestDashboardSuggestionWorkerCompleteCellCountsMissingLabelSetsAsRejected(t *testing.T) {
	db := newDashboardSuggestionWorkerTestDB(t)
	runID, sspID := seedDashboardSuggestionRun(t, db, dashboardSuggestionRunStatusRunning, 1)
	seedDashboardSuggestionCellWithLabelSets(t, db, runID, 0, dashboardSuggestionCellStatusPending, []string{"hash-with-evidence", "hash-without-evidence"})
	worker := NewDashboardSuggestionWorker(db, &llm.FakeClient{}, config.DefaultAIConfig(), zap.NewNop().Sugar())
	run := suggestionrel.DashboardSuggestionRun{
		UUIDModel:     relational.UUIDModel{ID: &runID},
		SSPID:         sspID,
		PromptVersion: suggestionrel.PromptVersion,
		Stats:         datatypes.JSONMap{},
	}
	cell := suggestionrel.DashboardSuggestionRunCell{RunID: runID, CellIndex: 0}
	catalogID := uuid.New()
	validation := suggestionrel.ValidationResult{
		Mappings: []suggestionrel.ValidatedMapping{{
			ControlKey:         suggestionrel.ControlKey(catalogID, "AC-1"),
			LabelSet:           map[string]string{"component": "api"},
			LabelSetHash:       "hash-with-evidence",
			ProposedFilterName: "API scope",
			Confidence:         0.8,
			Reasoning:          "evidence matches",
		}},
	}
	response := &llm.StructuredResponse{InputTokens: 2, OutputTokens: 3, CacheReadInputTokens: 5, CacheCreationInputTokens: 7}

	require.NoError(t, worker.completeCell(context.Background(), run, cell, response, validation, 1, 1))

	var stored suggestionrel.DashboardSuggestionRunCell
	require.NoError(t, db.First(&stored, "run_id = ? AND cell_index = ?", runID, 0).Error)
	require.Equal(t, dashboardSuggestionCellStatusCompleted, stored.Status)
	require.Equal(t, 5, stored.CacheReadInputTokens)
	require.Equal(t, 7, stored.CacheCreationInputTokens)
	require.Equal(t, 1, stored.MappingsReturned)
	require.Equal(t, 1, stored.MappingsRejected)

	var storedRun suggestionrel.DashboardSuggestionRun
	require.NoError(t, db.First(&storedRun, "id = ?", runID).Error)
	require.Equal(t, 5, storedRun.CacheReadInputTokens)
	require.Equal(t, 7, storedRun.CacheCreationInputTokens)
}

func TestDashboardSuggestionWorkerLLMRetryAndNonRetryableFailure(t *testing.T) {
	rendered := suggestionrel.RenderedPrompt{System: "system", Controls: "controls", Volatile: "labels"}

	t.Run("overloaded error retries once in job", func(t *testing.T) {
		fake := &llm.FakeClient{
			Errors: []error{llm.ErrOverloaded},
			Responses: []*llm.StructuredResponse{
				nil,
				{Raw: json.RawMessage(`{"mappings":[]}`), Model: "fake", InputTokens: 3, OutputTokens: 5},
			},
		}
		worker := NewDashboardSuggestionWorker(nil, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

		response, err := worker.completeWithRetry(context.Background(), rendered)
		require.NoError(t, err)
		require.Equal(t, 3, response.InputTokens)
		require.Equal(t, 5, response.OutputTokens)
		require.Len(t, fake.Requests, 2)
	})

	t.Run("rate limit is not retried inline", func(t *testing.T) {
		fake := &llm.FakeClient{Err: &llm.RateLimitError{RetryAfter: 5 * time.Second}}
		worker := NewDashboardSuggestionWorker(nil, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

		_, err := worker.completeWithRetry(context.Background(), rendered)
		require.ErrorIs(t, err, llm.ErrRateLimited)
		require.Len(t, fake.Requests, 1)
	})

	t.Run("non retryable error fails cell immediately", func(t *testing.T) {
		fake := &llm.FakeClient{Err: llm.ErrAuth}
		worker := NewDashboardSuggestionWorker(nil, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

		_, err := worker.completeWithRetry(context.Background(), rendered)
		require.ErrorIs(t, err, llm.ErrAuth)
		require.True(t, isNonRetryableLLMError(err))
		require.Len(t, fake.Requests, 1)
	})

	t.Run("cached request carries both cache breakpoints", func(t *testing.T) {
		fake := &llm.FakeClient{Raw: json.RawMessage(`{"mappings":[]}`)}
		worker := NewDashboardSuggestionWorker(nil, fake, config.DefaultAIConfig(), zap.NewNop().Sugar())

		_, err := worker.completeWithRetry(context.Background(), rendered)
		require.NoError(t, err)
		require.Len(t, fake.Requests, 1)
		req := fake.Requests[0]
		require.Equal(t, "system", req.System)
		require.Equal(t, llm.CacheTTL1h, req.SystemCacheTTL)
		require.Equal(t, "controls", req.CachedUserPrefix)
		require.Equal(t, llm.CacheTTL1h, req.CachedUserPrefixTTL)
		require.Equal(t, "labels", req.Prompt)
	})
}

func TestSnoozeDelay(t *testing.T) {
	t.Parallel()

	// With a Retry-After hint, the delay is at least the hint and within the
	// jitter band above it.
	for range 50 {
		d := snoozeDelay(12 * time.Second)
		require.GreaterOrEqual(t, d, 12*time.Second)
		require.Less(t, d, 12*time.Second+rateLimitSnoozeJitter)
	}

	// Without a hint, it falls back to the default base plus jitter.
	for range 50 {
		d := snoozeDelay(0)
		require.GreaterOrEqual(t, d, defaultRateLimitSnooze)
		require.Less(t, d, defaultRateLimitSnooze+rateLimitSnoozeJitter)
	}
}

func TestRateLimitSnooze(t *testing.T) {
	t.Parallel()

	t.Run("rate limit within budget snoozes", func(t *testing.T) {
		delay, ok := rateLimitSnooze(&llm.RateLimitError{RetryAfter: 7 * time.Second}, 1)
		require.True(t, ok)
		require.GreaterOrEqual(t, delay, 7*time.Second)
	})

	t.Run("wrapped rate limit is detected", func(t *testing.T) {
		wrapped := river.JobCancel(&llm.RateLimitError{RetryAfter: 2 * time.Second})
		_, ok := rateLimitSnooze(wrapped, 1)
		require.True(t, ok)
	})

	t.Run("exhausted budget does not snooze", func(t *testing.T) {
		_, ok := rateLimitSnooze(&llm.RateLimitError{RetryAfter: time.Second}, maxRateLimitSnoozes)
		require.False(t, ok)
	})

	t.Run("non rate limit does not snooze", func(t *testing.T) {
		_, ok := rateLimitSnooze(llm.ErrAuth, 1)
		require.False(t, ok)
	})

	// The bare ErrRateLimited sentinel is not a *RateLimitError, so it is not
	// snoozed (it carries no Retry-After) and falls through to normal handling.
	t.Run("bare sentinel does not snooze", func(t *testing.T) {
		_, ok := rateLimitSnooze(llm.ErrRateLimited, 1)
		require.False(t, ok)
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

func seedDashboardSuggestionCellWithLabelSets(t *testing.T, db *gorm.DB, runID uuid.UUID, cellIndex int, status string, labelSetHashes []string) {
	t.Helper()
	require.NoError(t, db.Create(&suggestionrel.DashboardSuggestionRunCell{
		RunID:          runID,
		CellIndex:      cellIndex,
		ControlKeys:    datatypes.NewJSONSlice([]string{}),
		LabelSetHashes: datatypes.NewJSONSlice(labelSetHashes),
		Status:         status,
	}).Error)
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
