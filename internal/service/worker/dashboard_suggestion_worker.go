package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/llm"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	dashboardSuggestionRunStatusPending   = "pending"
	dashboardSuggestionRunStatusRunning   = "running"
	dashboardSuggestionRunStatusCompleted = "completed"
	dashboardSuggestionRunStatusFailed    = "failed"

	dashboardSuggestionCellStatusPending   = "pending"
	dashboardSuggestionCellStatusCompleted = "completed"
	dashboardSuggestionCellStatusFailed    = "failed"
)

const (
	// defaultRateLimitSnooze is used when a 429 carries no Retry-After hint.
	// The ITPM limit replenishes per minute, so a sub-minute base is reasonable.
	defaultRateLimitSnooze = 30 * time.Second
	// rateLimitSnoozeJitter is the upper bound of random delay added to each
	// snooze to de-synchronise concurrently throttled workers.
	rateLimitSnoozeJitter = 15 * time.Second
	// maxRateLimitSnoozes caps how many times a cell may be snoozed before it is
	// failed, so a persistently throttled run cannot snooze forever.
	maxRateLimitSnoozes = 20
)

type DashboardSuggestionWorker struct {
	river.WorkerDefaults[DashboardSuggestionCellArgs]

	db                *gorm.DB
	suggestionService *suggestionrel.SuggestionService
	llmClient         llm.Client
	aiCfg             *config.AIConfig
	logger            *zap.SugaredLogger
}

func NewDashboardSuggestionWorker(db *gorm.DB, llmClient llm.Client, aiCfg *config.AIConfig, logger *zap.SugaredLogger) *DashboardSuggestionWorker {
	return &DashboardSuggestionWorker{
		db:                db,
		suggestionService: suggestionrel.NewSuggestionService(db),
		llmClient:         llmClient,
		aiCfg:             aiCfg,
		logger:            logger,
	}
}

func (w *DashboardSuggestionWorker) Timeout(job *river.Job[DashboardSuggestionCellArgs]) time.Duration {
	requestTimeout := dashboardSuggestionRequestTimeout(w.aiCfg)
	timeout := 2*requestTimeout + 30*time.Second
	if timeout < 5*time.Minute {
		return 5 * time.Minute
	}
	return timeout
}

func (w *DashboardSuggestionWorker) Work(ctx context.Context, job *river.Job[DashboardSuggestionCellArgs]) error {
	run, cell, ok, err := w.loadPendingCellAndStartRun(ctx, job.Args)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	gathered, err := w.suggestionService.GatherCellInput(run.SSPID, suggestionrel.GridCell{
		CellIndex:      cell.CellIndex,
		ControlKeys:    []string(cell.ControlKeys),
		LabelSetHashes: []string(cell.LabelSetHashes),
	}, suggestionrel.GatherOptions{})
	if err != nil {
		return w.handleAttemptFailure(ctx, job, err)
	}
	missingLabelSets := len(cell.LabelSetHashes) - len(gathered.LabelSets)
	if missingLabelSets < 0 {
		missingLabelSets = 0
	}

	rendered, err := suggestionrel.RenderPrompt(gathered)
	if err != nil {
		return w.handleAttemptFailure(ctx, job, err)
	}

	response, err := w.completeWithRetry(ctx, rendered)
	if err != nil {
		// A rate limit skips the cell and requeues it after the provider's
		// Retry-After (or a default) plus jitter, without consuming a regular
		// attempt or marking the cell failed.
		if delay, ok := rateLimitSnooze(err, job.Attempt); ok {
			return river.JobSnooze(delay)
		}
		// Non-retryable errors, and rate limits that have exhausted their snooze
		// budget, fail the cell and cancel the job.
		if isNonRetryableLLMError(err) || errors.Is(err, llm.ErrRateLimited) {
			if markErr := w.failCellAndMaybeFinalize(ctx, job.Args, err); markErr != nil {
				return markErr
			}
			return river.JobCancel(err)
		}
		return w.handleAttemptFailure(ctx, job, err)
	}

	if w.logger != nil {
		// Surface prompt-cache accounting so cache effectiveness is observable
		// without relying on the provider dashboard. cache_read_input_tokens are
		// the "cache hits"; cache_creation_input_tokens are first-time writes.
		w.logger.Infow("dashboard suggestion cell llm usage",
			"run_id", job.Args.RunID,
			"cell_index", cell.CellIndex,
			"input_tokens", response.InputTokens,
			"cache_creation_input_tokens", response.CacheCreationInputTokens,
			"cache_read_input_tokens", response.CacheReadInputTokens,
			"output_tokens", response.OutputTokens,
		)
	}

	rawCount, err := rawMappingCount(response.Raw)
	if err != nil {
		err = fmt.Errorf("%w: %v", llm.ErrInvalidOutput, err)
		if markErr := w.failCellAndMaybeFinalize(ctx, job.Args, err); markErr != nil {
			return markErr
		}
		return river.JobCancel(err)
	}

	validation, err := suggestionrel.ValidateMappings(gathered.CellInput(), response.Raw)
	if err != nil {
		err = fmt.Errorf("%w: %v", llm.ErrInvalidOutput, err)
		if markErr := w.failCellAndMaybeFinalize(ctx, job.Args, err); markErr != nil {
			return markErr
		}
		return river.JobCancel(err)
	}

	if err := w.completeCell(ctx, run, cell, response, validation, rawCount, missingLabelSets); err != nil {
		return w.handleAttemptFailure(ctx, job, err)
	}
	return nil
}

func (w *DashboardSuggestionWorker) loadPendingCellAndStartRun(ctx context.Context, args DashboardSuggestionCellArgs) (suggestionrel.DashboardSuggestionRun, suggestionrel.DashboardSuggestionRunCell, bool, error) {
	var run suggestionrel.DashboardSuggestionRun
	var cell suggestionrel.DashboardSuggestionRunCell
	err := w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("run_id = ? AND cell_index = ?", args.RunID, args.CellIndex).
			First(&cell).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if cell.Status != dashboardSuggestionCellStatusPending {
			return nil
		}
		if err := tx.Where("id = ?", args.RunID).First(&run).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		now := time.Now().UTC()
		update := tx.Model(&suggestionrel.DashboardSuggestionRun{}).
			Where("id = ? AND status = ?", args.RunID, dashboardSuggestionRunStatusPending).
			Updates(map[string]any{
				"status":     dashboardSuggestionRunStatusRunning,
				"started_at": now,
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected == 1 {
			run.Status = dashboardSuggestionRunStatusRunning
			run.StartedAt = &now
			return suggestionrel.CreateRunEventTx(tx, &run, suggestionrel.DashboardSuggestionEventTypeRunStarted, datatypes.JSONMap{
				"model":          run.Model,
				"prompt_version": run.PromptVersion,
			})
		}
		return nil
	})
	if err != nil {
		return suggestionrel.DashboardSuggestionRun{}, suggestionrel.DashboardSuggestionRunCell{}, false, err
	}
	if cell.Status != dashboardSuggestionCellStatusPending || run.ID == nil {
		return suggestionrel.DashboardSuggestionRun{}, suggestionrel.DashboardSuggestionRunCell{}, false, nil
	}
	return run, cell, true, nil
}

func (w *DashboardSuggestionWorker) completeWithRetry(ctx context.Context, rendered suggestionrel.RenderedPrompt) (*llm.StructuredResponse, error) {
	requestTimeout := dashboardSuggestionRequestTimeout(w.aiCfg)

	// Two prompt-cache breakpoints (1h TTL): the system block (run-stable) and
	// the controls prefix (row-stable). The volatile label-sets stay uncached.
	req := llm.StructuredRequest{
		System:              rendered.System,
		SystemCacheTTL:      llm.CacheTTL1h,
		CachedUserPrefix:    rendered.Controls,
		CachedUserPrefixTTL: llm.CacheTTL1h,
		Prompt:              rendered.Volatile,
		Schema:              suggestionrel.OutputSchema(),
		MaxTokens:           llm.DefaultAnthropicMaxTokens,
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		response, err := w.llmClient.CompleteStructured(callCtx, req)
		cancel()
		if err == nil {
			return response, nil
		}
		lastErr = err
		if !isInlineRetryableLLMError(err) {
			break
		}
	}
	return nil, lastErr
}

// rateLimitSnooze decides whether a failed completion should be snoozed. ok is
// false when err is not a rate limit, or when the snooze budget for this cell is
// exhausted (so the caller can fail it instead of snoozing forever).
func rateLimitSnooze(err error, attempt int) (time.Duration, bool) {
	var rateLimit *llm.RateLimitError
	if !errors.As(err, &rateLimit) {
		return 0, false
	}
	if attempt >= maxRateLimitSnoozes {
		return 0, false
	}
	return snoozeDelay(rateLimit.RetryAfter), true
}

// snoozeDelay returns how long to defer a rate-limited cell: the provider's
// Retry-After when available (otherwise a default), plus random jitter so the
// concurrent workers that all hit the limit at once do not wake in lockstep.
func snoozeDelay(retryAfter time.Duration) time.Duration {
	base := retryAfter
	if base <= 0 {
		base = defaultRateLimitSnooze
	}
	return base + rand.N(rateLimitSnoozeJitter)
}

func dashboardSuggestionRequestTimeout(aiCfg *config.AIConfig) time.Duration {
	if aiCfg != nil && aiCfg.RequestTimeout > 0 {
		return aiCfg.RequestTimeout
	}
	return config.DefaultAIConfig().RequestTimeout
}

func (w *DashboardSuggestionWorker) completeCell(
	ctx context.Context,
	run suggestionrel.DashboardSuggestionRun,
	cell suggestionrel.DashboardSuggestionRunCell,
	response *llm.StructuredResponse,
	validation suggestionrel.ValidationResult,
	rawCount int,
	missingLabelSets int,
) error {
	maxSuggestions := suggestionrel.DefaultMaxSuggestionsPerRun
	if w.aiCfg != nil && w.aiCfg.MaxSuggestionsPerRun > 0 {
		maxSuggestions = w.aiCfg.MaxSuggestionsPerRun
	}
	// mappings_rejected is an operational unserved count: invalid/excluded/capped
	// mappings plus requested label sets that had no gathered evidence.
	rejected := rawCount - len(validation.Mappings) + missingLabelSets
	if rejected < 0 {
		rejected = 0
	}

	return w.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lockedCell suggestionrel.DashboardSuggestionRunCell
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("run_id = ? AND cell_index = ?", *run.ID, cell.CellIndex).
			First(&lockedCell).Error; err != nil {
			return err
		}
		if lockedCell.Status != dashboardSuggestionCellStatusPending {
			return nil
		}

		inserted, err := w.suggestionService.InsertValidatedMappingsTx(tx, *run.ID, run.SSPID, run.PromptVersion, validation.Mappings, maxSuggestions)
		if err != nil {
			return err
		}
		rejected += inserted.Excluded + inserted.Capped
		now := time.Now().UTC()
		update := tx.Model(&suggestionrel.DashboardSuggestionRunCell{}).
			Where("run_id = ? AND cell_index = ? AND status = ?", *run.ID, cell.CellIndex, dashboardSuggestionCellStatusPending).
			Updates(map[string]any{
				"status":            dashboardSuggestionCellStatusCompleted,
				"error":             nil,
				"input_tokens":      response.InputTokens,
				"output_tokens":     response.OutputTokens,
				"mappings_returned": rawCount,
				"mappings_rejected": rejected,
				"completed_at":      now,
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected == 0 {
			return nil
		}
		return w.finalizeRunIfReady(tx, *run.ID)
	})
}

func (w *DashboardSuggestionWorker) handleAttemptFailure(ctx context.Context, job *river.Job[DashboardSuggestionCellArgs], err error) error {
	if isFinalAttempt(job) {
		if markErr := w.failCellAndMaybeFinalize(ctx, job.Args, err); markErr != nil {
			if w.logger != nil {
				w.logger.Errorw("failed to mark dashboard suggestion cell failed on final attempt",
					"run_id", job.Args.RunID,
					"cell_index", job.Args.CellIndex,
					"error", err,
					"mark_error", markErr,
				)
			}
			return markErr
		}
	}
	return err
}

func (w *DashboardSuggestionWorker) failCellAndMaybeFinalize(ctx context.Context, args DashboardSuggestionCellArgs, cause error) error {
	detachedCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	return w.db.WithContext(detachedCtx).Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()
		message := cause.Error()
		update := tx.Model(&suggestionrel.DashboardSuggestionRunCell{}).
			Where("run_id = ? AND cell_index = ? AND status = ?", args.RunID, args.CellIndex, dashboardSuggestionCellStatusPending).
			Updates(map[string]any{
				"status":       dashboardSuggestionCellStatusFailed,
				"error":        message,
				"completed_at": now,
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected == 0 {
			return nil
		}
		return w.finalizeRunIfReady(tx, args.RunID)
	})
}

func (w *DashboardSuggestionWorker) finalizeRunIfReady(tx *gorm.DB, runID uuid.UUID) error {
	var run suggestionrel.DashboardSuggestionRun
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", runID).First(&run).Error; err != nil {
		return err
	}
	if run.Status == dashboardSuggestionRunStatusCompleted || run.Status == dashboardSuggestionRunStatusFailed {
		return nil
	}

	var pending int64
	if err := tx.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Where("run_id = ? AND status = ?", runID, dashboardSuggestionCellStatusPending).
		Count(&pending).Error; err != nil {
		return err
	}
	if pending > 0 {
		return nil
	}

	type aggregateRow struct {
		Completed        int
		Failed           int
		InputTokens      int
		OutputTokens     int
		MappingsReturned int
		MappingsRejected int
	}
	var aggregate aggregateRow
	if err := tx.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Select(`
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS completed,
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS failed,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(mappings_returned), 0) AS mappings_returned,
			COALESCE(SUM(mappings_rejected), 0) AS mappings_rejected
		`, dashboardSuggestionCellStatusCompleted, dashboardSuggestionCellStatusFailed).
		Where("run_id = ?", runID).
		Scan(&aggregate).Error; err != nil {
		return err
	}

	var failedCells []suggestionrel.DashboardSuggestionRunCell
	if err := tx.Where("run_id = ? AND status = ?", runID, dashboardSuggestionCellStatusFailed).
		Order("cell_index ASC").
		Find(&failedCells).Error; err != nil {
		return err
	}

	failedSummary := make([]any, 0, len(failedCells))
	for _, cell := range failedCells {
		item := datatypes.JSONMap{"cell_index": cell.CellIndex}
		if cell.Error != nil {
			item["error"] = *cell.Error
		}
		failedSummary = append(failedSummary, item)
	}

	stats := datatypes.JSONMap{}
	for key, value := range run.Stats {
		stats[key] = value
	}
	stats["cells_completed"] = aggregate.Completed
	stats["cells_failed"] = aggregate.Failed
	stats["failed_cells"] = failedSummary
	stats["mappings_returned"] = aggregate.MappingsReturned
	stats["mappings_rejected"] = aggregate.MappingsRejected

	status := dashboardSuggestionRunStatusCompleted
	eventType := suggestionrel.DashboardSuggestionEventTypeRunCompleted
	if aggregate.Completed == 0 {
		status = dashboardSuggestionRunStatusFailed
		eventType = suggestionrel.DashboardSuggestionEventTypeRunFailed
	}
	now := time.Now().UTC()
	if err := tx.Model(&suggestionrel.DashboardSuggestionRun{}).
		Where("id = ?", runID).
		Updates(map[string]any{
			"status":        status,
			"completed_at":  now,
			"input_tokens":  aggregate.InputTokens,
			"output_tokens": aggregate.OutputTokens,
			"stats":         stats,
		}).Error; err != nil {
		return err
	}
	run.Status = status
	run.CompletedAt = &now
	run.InputTokens = aggregate.InputTokens
	run.OutputTokens = aggregate.OutputTokens
	run.Stats = stats
	return suggestionrel.CreateRunEventTx(tx, &run, eventType, datatypes.JSONMap{
		"cells_completed": aggregate.Completed,
		"cells_failed":    aggregate.Failed,
	})
}

func rawMappingCount(raw json.RawMessage) (int, error) {
	var decoded suggestionrel.RawMappings
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return 0, err
	}
	return len(decoded.Mappings), nil
}

// isInlineRetryableLLMError reports whether an immediate in-process retry is
// worthwhile. Overloaded errors are transient and worth one quick retry; rate
// limits are deliberately excluded so they bubble up to be snoozed instead of
// burning another call into the same throttled window.
func isInlineRetryableLLMError(err error) bool {
	if errors.Is(err, llm.ErrRateLimited) {
		return false
	}
	return errors.Is(err, llm.ErrOverloaded)
}

func isNonRetryableLLMError(err error) bool {
	return errors.Is(err, llm.ErrAuth) || errors.Is(err, llm.ErrInvalidOutput)
}

func isFinalAttempt(job *river.Job[DashboardSuggestionCellArgs]) bool {
	if job == nil || job.JobRow == nil {
		return false
	}
	maxAttempts := job.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = DashboardSuggestionMaxAttempts
	}
	return job.Attempt >= maxAttempts
}
