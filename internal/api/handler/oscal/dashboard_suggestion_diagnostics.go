package oscal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	workersvc "github.com/compliance-framework/api/internal/service/worker"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const aiDiagnosticsQueueName = workersvc.DashboardSuggestionQueue

type AiDiagnosticsHandler struct {
	sugar *zap.SugaredLogger
	db    *gorm.DB
	cfg   *config.AIConfig
}

type AiDiagnosticsSummary struct {
	Enabled bool                       `json:"enabled"`
	Config  AiDiagnosticsConfig        `json:"config"`
	Totals  AiDiagnosticsTotals        `json:"totals"`
	Queue   *AiDiagnosticsQueue        `json:"queue"`
	Checks  []AiDiagnosticsHealthCheck `json:"checks"`
}

type AiDiagnosticsConfig struct {
	Model                string `json:"model"`
	PromptVersion        string `json:"promptVersion"`
	MaxControlsPerChunk  int    `json:"maxControlsPerChunk"`
	MaxLabelSetsPerChunk int    `json:"maxLabelSetsPerChunk"`
	MaxCallsPerRun       int    `json:"maxCallsPerRun"`
	QueueWorkers         int    `json:"queueWorkers"`
}

type AiDiagnosticsTotals struct {
	Runs                     int64            `json:"runs"`
	RunsByStatus             map[string]int64 `json:"runsByStatus"`
	CellsCompleted           int64            `json:"cellsCompleted"`
	CellsFailed              int64            `json:"cellsFailed"`
	InputTokens              int64            `json:"inputTokens"`
	OutputTokens             int64            `json:"outputTokens"`
	CacheReadInputTokens     int64            `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int64            `json:"cacheCreationInputTokens"`
	CacheHitRatio            float64          `json:"cacheHitRatio"`
	MappingsReturned         int64            `json:"mappingsReturned"`
	MappingsRejected         int64            `json:"mappingsRejected"`
	SuggestionsAccepted      int64            `json:"suggestionsAccepted"`
	SuggestionsRejected      int64            `json:"suggestionsRejected"`
	SuggestionsPending       int64            `json:"suggestionsPending"`
	RateLimitedTotal         int64            `json:"rateLimitedTotal"`
}

type AiDiagnosticsQueue struct {
	Name              string     `json:"name"`
	MaxWorkers        int        `json:"maxWorkers"`
	Available         int64      `json:"available"`
	Running           int64      `json:"running"`
	Retryable         int64      `json:"retryable"`
	Scheduled         int64      `json:"scheduled"`
	Completed24h      int64      `json:"completed24h"`
	Discarded24h      int64      `json:"discarded24h"`
	OldestAvailableAt *time.Time `json:"oldestAvailableAt"`
}

type AiDiagnosticsHealthCheck struct {
	ID                 string   `json:"id"`
	Status             string   `json:"status"`
	Message            string   `json:"message"`
	RecommendedActions []string `json:"recommendedActions"`
}

type AiDiagnosticsRun struct {
	ID                       string                `json:"id"`
	SSPID                    string                `json:"sspId"`
	SSPName                  string                `json:"sspName"`
	Status                   string                `json:"status"`
	Model                    string                `json:"model"`
	PromptVersion            string                `json:"promptVersion"`
	PlannedCalls             int                   `json:"plannedCalls"`
	CompletedCells           int                   `json:"completedCells"`
	FailedCells              int                   `json:"failedCells"`
	InputTokens              int                   `json:"inputTokens"`
	OutputTokens             int                   `json:"outputTokens"`
	CacheReadInputTokens     int                   `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int                   `json:"cacheCreationInputTokens"`
	CacheHitRatio            float64               `json:"cacheHitRatio"`
	MappingsReturned         int                   `json:"mappingsReturned"`
	MappingsRejected         int                   `json:"mappingsRejected"`
	RateLimitedTotal         int                   `json:"rateLimitedTotal"`
	StartedAt                *time.Time            `json:"startedAt"`
	CompletedAt              *time.Time            `json:"completedAt"`
	DurationMs               int64                 `json:"durationMs"`
	TriggeredBy              *suggestionEventActor `json:"triggeredBy,omitempty"`
}

type AiDiagnosticsRunCell struct {
	CellIndex                int        `json:"cellIndex"`
	Status                   string     `json:"status"`
	ControlKeys              []string   `json:"controlKeys"`
	LabelSetHashes           []string   `json:"labelSetHashes"`
	InputTokens              int        `json:"inputTokens"`
	OutputTokens             int        `json:"outputTokens"`
	CacheReadInputTokens     int        `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int        `json:"cacheCreationInputTokens"`
	RateLimitedCount         int        `json:"rateLimitedCount"`
	MappingsReturned         int        `json:"mappingsReturned"`
	MappingsRejected         int        `json:"mappingsRejected"`
	Error                    *string    `json:"error"`
	CompletedAt              *time.Time `json:"completedAt"`
}

type AiDiagnosticsRunDetail struct {
	AiDiagnosticsRun
	Cells  []AiDiagnosticsRunCell             `json:"cells"`
	Events []dashboardSuggestionEventResponse `json:"events"`
}

type aiDiagnosticsListMeta struct {
	NextCursor string `json:"nextCursor,omitempty"`
}

type aiDiagnosticsCursor struct {
	StartedAt time.Time `json:"startedAt"`
	ID        string    `json:"id"`
}

type aiDiagnosticsRunRow struct {
	suggestionrel.DashboardSuggestionRun
	SSPName                  *string `gorm:"column:ssp_name"`
	CompletedCells           int     `gorm:"column:completed_cells"`
	FailedCells              int     `gorm:"column:failed_cells"`
	InputTokens              int     `gorm:"column:cell_input_tokens"`
	OutputTokens             int     `gorm:"column:cell_output_tokens"`
	CacheReadInputTokens     int     `gorm:"column:cell_cache_read_input_tokens"`
	CacheCreationInputTokens int     `gorm:"column:cell_cache_creation_input_tokens"`
	RateLimitedCount         int     `gorm:"column:cell_rate_limited_count"`
	MappingsReturned         int     `gorm:"column:mappings_returned"`
	MappingsRejected         int     `gorm:"column:mappings_rejected"`
}

func NewAiDiagnosticsHandler(sugar *zap.SugaredLogger, db *gorm.DB, cfg *config.AIConfig) *AiDiagnosticsHandler {
	return &AiDiagnosticsHandler{sugar: sugar, db: db, cfg: cfg}
}

func (h *AiDiagnosticsHandler) Register(apiGroup *echo.Group) {
	apiGroup.GET("/summary", h.Summary)
	apiGroup.GET("/runs", h.Runs)
	apiGroup.GET("/runs/:runId", h.RunDetail)
}

// Summary godoc
//
//	@Summary		Get AI diagnostics summary
//	@Description	Returns cross-SSP dashboard suggestion totals, suggestion queue stats, and health checks for admins.
//	@Tags			AI Diagnostics
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscal.AiDiagnosticsSummary]
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/ai-diagnostics/summary [get]
func (h *AiDiagnosticsHandler) Summary(ctx echo.Context) error {
	totals, recent, err := h.loadTotals(ctx.Request().Context())
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	queue, queueErr := h.loadQueue(ctx.Request().Context())
	if queueErr != nil && h.sugar != nil {
		h.sugar.Warnw("failed to load AI diagnostics queue stats", "error", queueErr)
	}
	response := AiDiagnosticsSummary{
		Enabled: h.aiEnabled(),
		Config:  h.configResponse(),
		Totals:  totals,
		Queue:   queue,
		Checks:  h.checks(totals, recent, queue, queueErr),
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[AiDiagnosticsSummary]{Data: response})
}

// Runs godoc
//
//	@Summary		List AI diagnostic runs
//	@Description	Lists dashboard suggestion runs across all SSPs, newest first, with optional status and SSP filters.
//	@Tags			AI Diagnostics
//	@Produce		json
//	@Param			status	query		string	false	"Run status"	Enums(pending, running, completed, failed)
//	@Param			sspId	query		string	false	"System Security Plan ID"
//	@Param			limit	query		int		false	"Page size, default 25, max 100"	minimum(1)	maximum(100)
//	@Param			cursor	query		string	false	"Opaque pagination cursor"
//	@Success		200		{object}	handler.GenericDataListResponse[oscal.AiDiagnosticsRun]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/ai-diagnostics/runs [get]
func (h *AiDiagnosticsHandler) Runs(ctx echo.Context) error {
	query, err := parseAiDiagnosticsRunsQuery(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	runs, nextCursor, err := h.loadRuns(ctx.Request().Context(), query)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[AiDiagnosticsRun]{
		Data: runs,
		Meta: aiDiagnosticsListMeta{NextCursor: nextCursor},
	})
}

// RunDetail godoc
//
//	@Summary		Get AI diagnostic run detail
//	@Description	Returns one dashboard suggestion run with cells and events.
//	@Tags			AI Diagnostics
//	@Produce		json
//	@Param			runId	path		string	true	"Dashboard suggestion run ID"
//	@Success		200		{object}	handler.GenericDataResponse[oscal.AiDiagnosticsRunDetail]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/admin/ai-diagnostics/runs/{runId} [get]
func (h *AiDiagnosticsHandler) RunDetail(ctx echo.Context) error {
	runID, err := uuid.Parse(ctx.Param("runId"))
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	runs, _, err := h.loadRuns(ctx.Request().Context(), aiDiagnosticsRunsQuery{runID: &runID, limit: 1})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if len(runs) == 0 {
		return ctx.JSON(http.StatusNotFound, api.NotFound())
	}

	var cells []suggestionrel.DashboardSuggestionRunCell
	if err := h.db.WithContext(ctx.Request().Context()).
		Where("run_id = ?", runID).
		Order("cell_index ASC").
		Find(&cells).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	cellResponses := make([]AiDiagnosticsRunCell, 0, len(cells))
	for _, cell := range cells {
		cellResponses = append(cellResponses, AiDiagnosticsRunCell{
			CellIndex:                cell.CellIndex,
			Status:                   cell.Status,
			ControlKeys:              []string(cell.ControlKeys),
			LabelSetHashes:           []string(cell.LabelSetHashes),
			InputTokens:              cell.InputTokens,
			OutputTokens:             cell.OutputTokens,
			CacheReadInputTokens:     cell.CacheReadInputTokens,
			CacheCreationInputTokens: cell.CacheCreationInputTokens,
			RateLimitedCount:         cell.RateLimitedCount,
			MappingsReturned:         cell.MappingsReturned,
			MappingsRejected:         cell.MappingsRejected,
			Error:                    cell.Error,
			CompletedAt:              cell.CompletedAt,
		})
	}

	var events []suggestionrel.DashboardSuggestionEvent
	if err := h.db.WithContext(ctx.Request().Context()).
		Where("run_id = ?", runID).
		Order("occurred_at ASC").
		Find(&events).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	eventResponses, err := h.eventResponses(events)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[AiDiagnosticsRunDetail]{
		Data: AiDiagnosticsRunDetail{AiDiagnosticsRun: runs[0], Cells: cellResponses, Events: eventResponses},
	})
}

type aiDiagnosticsRunsQuery struct {
	status string
	sspID  *uuid.UUID
	limit  int
	cursor *aiDiagnosticsCursor
	runID  *uuid.UUID
}

func parseAiDiagnosticsRunsQuery(ctx echo.Context) (aiDiagnosticsRunsQuery, error) {
	limit := 25
	if raw := strings.TrimSpace(ctx.QueryParam("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			return aiDiagnosticsRunsQuery{}, errors.New("invalid limit")
		}
		limit = parsed
	}
	if limit > 100 {
		limit = 100
	}
	status := strings.TrimSpace(ctx.QueryParam("status"))
	if status != "" {
		switch status {
		case "pending", "running", "completed", "failed":
		default:
			return aiDiagnosticsRunsQuery{}, errors.New("invalid status")
		}
	}
	var sspID *uuid.UUID
	if raw := strings.TrimSpace(ctx.QueryParam("sspId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return aiDiagnosticsRunsQuery{}, errors.New("invalid sspId")
		}
		sspID = &parsed
	}
	var cursor *aiDiagnosticsCursor
	if raw := strings.TrimSpace(ctx.QueryParam("cursor")); raw != "" {
		parsed, err := decodeAiDiagnosticsCursor(raw)
		if err != nil {
			return aiDiagnosticsRunsQuery{}, errors.New("invalid cursor")
		}
		cursor = &parsed
	}
	return aiDiagnosticsRunsQuery{status: status, sspID: sspID, limit: limit, cursor: cursor}, nil
}

func (h *AiDiagnosticsHandler) loadTotals(ctx context.Context) (AiDiagnosticsTotals, recentCellTotals, error) {
	totals := AiDiagnosticsTotals{
		RunsByStatus: map[string]int64{
			"pending":   0,
			"running":   0,
			"completed": 0,
			"failed":    0,
		},
	}

	var runRows []struct {
		Status string
		Count  int64
	}
	if err := h.db.WithContext(ctx).
		Model(&suggestionrel.DashboardSuggestionRun{}).
		Select(`
			status,
			count(*) AS count
		`).
		Group("status").
		Scan(&runRows).Error; err != nil {
		return totals, recentCellTotals{}, err
	}
	for _, row := range runRows {
		totals.Runs += row.Count
		totals.RunsByStatus[row.Status] = row.Count
	}

	var cellTotals struct {
		CellsCompleted           int64
		CellsFailed              int64
		InputTokens              int64
		OutputTokens             int64
		CacheReadInputTokens     int64
		CacheCreationInputTokens int64
		RateLimitedCount         int64
		MappingsReturned         int64
		MappingsRejected         int64
	}
	if err := h.db.WithContext(ctx).
		Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Select(`
			COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) AS cells_completed,
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS cells_failed,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(cache_read_input_tokens), 0) AS cache_read_input_tokens,
			COALESCE(SUM(cache_creation_input_tokens), 0) AS cache_creation_input_tokens,
			COALESCE(SUM(rate_limited_count), 0) AS rate_limited_count,
			COALESCE(SUM(mappings_returned), 0) AS mappings_returned,
			COALESCE(SUM(mappings_rejected), 0) AS mappings_rejected
		`).
		Scan(&cellTotals).Error; err != nil {
		return totals, recentCellTotals{}, err
	}
	totals.CellsCompleted = cellTotals.CellsCompleted
	totals.CellsFailed = cellTotals.CellsFailed
	totals.InputTokens = cellTotals.InputTokens
	totals.OutputTokens = cellTotals.OutputTokens
	totals.CacheReadInputTokens = cellTotals.CacheReadInputTokens
	totals.CacheCreationInputTokens = cellTotals.CacheCreationInputTokens
	totals.RateLimitedTotal = cellTotals.RateLimitedCount
	totals.MappingsReturned = cellTotals.MappingsReturned
	totals.MappingsRejected = cellTotals.MappingsRejected

	var suggestionRows []struct {
		Status string
		Count  int64
	}
	if err := h.db.WithContext(ctx).
		Model(&suggestionrel.DashboardSuggestion{}).
		Select("status, count(*) AS count").
		Group("status").
		Scan(&suggestionRows).Error; err != nil {
		return totals, recentCellTotals{}, err
	}
	for _, row := range suggestionRows {
		switch row.Status {
		case suggestionrel.DashboardSuggestionStatusAccepted:
			totals.SuggestionsAccepted = row.Count
		case suggestionrel.DashboardSuggestionStatusRejected:
			totals.SuggestionsRejected = row.Count
		case suggestionrel.DashboardSuggestionStatusPending:
			totals.SuggestionsPending = row.Count
		}
	}
	totals.CacheHitRatio = cacheHitRatio(int(totals.InputTokens), int(totals.CacheReadInputTokens), int(totals.CacheCreationInputTokens))

	recent, err := h.loadRecentCellTotals(ctx)
	if err != nil {
		return totals, recentCellTotals{}, err
	}
	return totals, recent, nil
}

type recentCellTotals struct {
	Completed int64
	Failed    int64
}

func (h *AiDiagnosticsHandler) loadRecentCellTotals(ctx context.Context) (recentCellTotals, error) {
	var recent recentCellTotals
	err := h.db.WithContext(ctx).
		Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Select(`
			COALESCE(SUM(CASE WHEN dashboard_suggestion_run_cells.status = 'completed' THEN 1 ELSE 0 END), 0) AS completed,
			COALESCE(SUM(CASE WHEN dashboard_suggestion_run_cells.status = 'failed' THEN 1 ELSE 0 END), 0) AS failed
		`).
		Where("dashboard_suggestion_run_cells.status IN ? AND dashboard_suggestion_run_cells.completed_at >= ?", []string{"completed", "failed"}, time.Now().UTC().Add(-24*time.Hour)).
		Scan(&recent).Error
	return recent, err
}

func (h *AiDiagnosticsHandler) loadQueue(ctx context.Context) (*AiDiagnosticsQueue, error) {
	queue := &AiDiagnosticsQueue{Name: aiDiagnosticsQueueName, MaxWorkers: h.queueWorkers()}
	if !h.db.Migrator().HasTable("river_job") {
		return nil, errors.New("river_job table is not available")
	}

	var stateRows []struct {
		State string
		Count int64
	}
	if err := h.db.WithContext(ctx).Table("river_job").
		Select("state::text AS state, count(*) AS count").
		Where("queue = ?", aiDiagnosticsQueueName).
		Group("state").
		Find(&stateRows).Error; err != nil {
		return nil, fmt.Errorf("computing suggestion queue states: %w", err)
	}
	for _, row := range stateRows {
		switch row.State {
		case "available":
			queue.Available = row.Count
		case "running":
			queue.Running = row.Count
		case "retryable":
			queue.Retryable = row.Count
		case "scheduled":
			queue.Scheduled = row.Count
		}
	}

	now := time.Now().UTC()
	var finalized struct {
		Completed24h int64 `gorm:"column:completed24h"`
		Discarded24h int64 `gorm:"column:discarded24h"`
	}
	if err := h.db.WithContext(ctx).Table("river_job").
		Select(`
			COALESCE(SUM(CASE WHEN state = 'completed' AND finalized_at >= ? THEN 1 ELSE 0 END), 0) AS completed24h,
			COALESCE(SUM(CASE WHEN state = 'discarded' AND finalized_at >= ? THEN 1 ELSE 0 END), 0) AS discarded24h
		`, now.Add(-24*time.Hour), now.Add(-24*time.Hour)).
		Where("queue = ?", aiDiagnosticsQueueName).
		Scan(&finalized).Error; err != nil {
		return nil, fmt.Errorf("computing suggestion queue finalized counts: %w", err)
	}
	queue.Completed24h = finalized.Completed24h
	queue.Discarded24h = finalized.Discarded24h

	var waiting struct {
		OldestAvailableAt *time.Time `gorm:"column:oldest_available_at"`
	}
	if err := h.db.WithContext(ctx).Table("river_job").
		Select("min(CASE WHEN state IN ? AND scheduled_at <= ? THEN scheduled_at END) AS oldest_available_at", []string{"available", "retryable", "scheduled"}, now).
		Where("queue = ?", aiDiagnosticsQueueName).
		Scan(&waiting).Error; err != nil {
		return nil, fmt.Errorf("computing suggestion queue oldest available job: %w", err)
	}
	queue.OldestAvailableAt = waiting.OldestAvailableAt
	return queue, nil
}

func (h *AiDiagnosticsHandler) loadRuns(ctx context.Context, query aiDiagnosticsRunsQuery) ([]AiDiagnosticsRun, string, error) {
	dbq := h.db.WithContext(ctx).
		Model(&suggestionrel.DashboardSuggestionRun{}).
		Select(`
			dashboard_suggestion_runs.*,
			metadata.title AS ssp_name,
			COALESCE(cell_progress.completed_cells, 0) AS completed_cells,
			COALESCE(cell_progress.failed_cells, 0) AS failed_cells,
			COALESCE(cell_progress.input_tokens, 0) AS cell_input_tokens,
			COALESCE(cell_progress.output_tokens, 0) AS cell_output_tokens,
			COALESCE(cell_progress.cache_read_input_tokens, 0) AS cell_cache_read_input_tokens,
			COALESCE(cell_progress.cache_creation_input_tokens, 0) AS cell_cache_creation_input_tokens,
			COALESCE(cell_progress.rate_limited_count, 0) AS cell_rate_limited_count,
			COALESCE(cell_progress.mappings_returned, 0) AS mappings_returned,
			COALESCE(cell_progress.mappings_rejected, 0) AS mappings_rejected
		`).
		Joins("LEFT JOIN metadata ON metadata.parent_id::text = dashboard_suggestion_runs.ssp_id::text AND metadata.parent_type = ?", "system_security_plans").
		Joins(`LEFT JOIN (
			SELECT
				run_id,
				SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_cells,
				SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_cells,
				SUM(input_tokens) AS input_tokens,
				SUM(output_tokens) AS output_tokens,
				SUM(cache_read_input_tokens) AS cache_read_input_tokens,
				SUM(cache_creation_input_tokens) AS cache_creation_input_tokens,
				SUM(rate_limited_count) AS rate_limited_count,
				SUM(mappings_returned) AS mappings_returned,
				SUM(mappings_rejected) AS mappings_rejected
			FROM dashboard_suggestion_run_cells
			GROUP BY run_id
		) cell_progress ON cell_progress.run_id = dashboard_suggestion_runs.id`)
	if query.runID != nil {
		dbq = dbq.Where("dashboard_suggestion_runs.id = ?", *query.runID)
	}
	if query.status != "" {
		dbq = dbq.Where("dashboard_suggestion_runs.status = ?", query.status)
	}
	if query.sspID != nil {
		dbq = dbq.Where("dashboard_suggestion_runs.ssp_id = ?", *query.sspID)
	}
	if query.cursor != nil {
		cursorID, err := uuid.Parse(query.cursor.ID)
		if err != nil {
			return nil, "", err
		}
		dbq = dbq.Where(
			"(dashboard_suggestion_runs.started_at < ? OR (dashboard_suggestion_runs.started_at = ? AND dashboard_suggestion_runs.id < ?))",
			query.cursor.StartedAt, query.cursor.StartedAt, cursorID,
		)
	}

	var rows []aiDiagnosticsRunRow
	if err := dbq.
		Order("dashboard_suggestion_runs.started_at DESC NULLS LAST, dashboard_suggestion_runs.id DESC").
		Limit(query.limit + 1).
		Scan(&rows).Error; err != nil {
		return nil, "", err
	}

	nextCursor := ""
	if len(rows) > query.limit {
		last := rows[query.limit-1]
		if last.StartedAt != nil && last.ID != nil {
			nextCursor = encodeAiDiagnosticsCursor(aiDiagnosticsCursor{StartedAt: *last.StartedAt, ID: last.ID.String()})
		}
		rows = rows[:query.limit]
	}

	actors, err := h.resolveRunActors(rows)
	if err != nil {
		return nil, "", err
	}
	out := make([]AiDiagnosticsRun, 0, len(rows))
	for _, row := range rows {
		run := row.DashboardSuggestionRun
		run.InputTokens = row.InputTokens
		run.OutputTokens = row.OutputTokens
		run.CacheReadInputTokens = row.CacheReadInputTokens
		run.CacheCreationInputTokens = row.CacheCreationInputTokens
		run.RateLimitedCount = row.RateLimitedCount
		out = append(out, h.runResponse(run, row.SSPName, row.CompletedCells, row.FailedCells, row.MappingsReturned, row.MappingsRejected, actors))
	}
	return out, nextCursor, nil
}

func (h *AiDiagnosticsHandler) runResponse(
	run suggestionrel.DashboardSuggestionRun,
	sspName *string,
	completedCells int,
	failedCells int,
	mappingsReturned int,
	mappingsRejected int,
	actors map[uuid.UUID]suggestionEventActor,
) AiDiagnosticsRun {
	id := ""
	if run.ID != nil {
		id = run.ID.String()
	}
	name := ""
	if sspName != nil {
		name = *sspName
	}
	var triggeredBy *suggestionEventActor
	if run.TriggeredByUserID != nil {
		if actor, ok := actors[*run.TriggeredByUserID]; ok {
			triggeredBy = &actor
		}
	}
	return AiDiagnosticsRun{
		ID:                       id,
		SSPID:                    run.SSPID.String(),
		SSPName:                  name,
		Status:                   run.Status,
		Model:                    run.Model,
		PromptVersion:            run.PromptVersion,
		PlannedCalls:             run.PlannedCalls,
		CompletedCells:           completedCells,
		FailedCells:              failedCells,
		InputTokens:              run.InputTokens,
		OutputTokens:             run.OutputTokens,
		CacheReadInputTokens:     run.CacheReadInputTokens,
		CacheCreationInputTokens: run.CacheCreationInputTokens,
		CacheHitRatio:            cacheHitRatio(run.InputTokens, run.CacheReadInputTokens, run.CacheCreationInputTokens),
		MappingsReturned:         mappingsReturned,
		MappingsRejected:         mappingsRejected,
		RateLimitedTotal:         run.RateLimitedCount,
		StartedAt:                run.StartedAt,
		CompletedAt:              run.CompletedAt,
		DurationMs:               durationMs(run.StartedAt, run.CompletedAt),
		TriggeredBy:              triggeredBy,
	}
}

func (h *AiDiagnosticsHandler) resolveRunActors(rows []aiDiagnosticsRunRow) (map[uuid.UUID]suggestionEventActor, error) {
	ids := make([]uuid.UUID, 0, len(rows))
	seen := make(map[uuid.UUID]struct{}, len(rows))
	for _, row := range rows {
		if row.TriggeredByUserID == nil {
			continue
		}
		if _, ok := seen[*row.TriggeredByUserID]; ok {
			continue
		}
		seen[*row.TriggeredByUserID] = struct{}{}
		ids = append(ids, *row.TriggeredByUserID)
	}
	return h.resolveActors(ids)
}

func (h *AiDiagnosticsHandler) eventResponses(events []suggestionrel.DashboardSuggestionEvent) ([]dashboardSuggestionEventResponse, error) {
	ids := make([]uuid.UUID, 0, len(events))
	seen := make(map[uuid.UUID]struct{}, len(events))
	for _, event := range events {
		if event.ActorUserID == nil {
			continue
		}
		if _, ok := seen[*event.ActorUserID]; ok {
			continue
		}
		seen[*event.ActorUserID] = struct{}{}
		ids = append(ids, *event.ActorUserID)
	}
	actors, err := h.resolveActors(ids)
	if err != nil {
		return nil, err
	}
	out := make([]dashboardSuggestionEventResponse, 0, len(events))
	for _, event := range events {
		resp := dashboardSuggestionEventResponse{DashboardSuggestionEvent: event}
		if event.ActorUserID != nil {
			if actor, ok := actors[*event.ActorUserID]; ok {
				resp.Actor = &actor
			}
		}
		out = append(out, resp)
	}
	return out, nil
}

func (h *AiDiagnosticsHandler) resolveActors(ids []uuid.UUID) (map[uuid.UUID]suggestionEventActor, error) {
	actors := make(map[uuid.UUID]suggestionEventActor, len(ids))
	if len(ids) == 0 {
		return actors, nil
	}
	var users []relational.User
	if err := h.db.Where("id IN ?", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.ID == nil {
			continue
		}
		actors[*user.ID] = suggestionEventActor{ID: user.ID.String(), Name: handler.UserDisplayName(user)}
	}
	return actors, nil
}

func (h *AiDiagnosticsHandler) checks(totals AiDiagnosticsTotals, recent recentCellTotals, queue *AiDiagnosticsQueue, queueErr error) []AiDiagnosticsHealthCheck {
	checks := []AiDiagnosticsHealthCheck{
		h.aiEnabledCheck(),
		h.workerRegisteredCheck(),
		h.queueReachableCheck(queue, queueErr),
		h.recentFailureRateCheck(recent),
		h.cacheEngagingCheck(totals),
		h.rateLimitPressureCheck(totals),
	}
	return checks
}

func (h *AiDiagnosticsHandler) aiEnabledCheck() AiDiagnosticsHealthCheck {
	if h.aiEnabled() {
		return AiDiagnosticsHealthCheck{ID: "ai_enabled", Status: "pass", Message: "AI dashboard suggestions are enabled.", RecommendedActions: []string{}}
	}
	return AiDiagnosticsHealthCheck{ID: "ai_enabled", Status: "fail", Message: "AI dashboard suggestions are disabled.", RecommendedActions: []string{"Set CCF_AI_ENABLED=true and restart the API and workers."}}
}

func (h *AiDiagnosticsHandler) workerRegisteredCheck() AiDiagnosticsHealthCheck {
	if h.queueWorkers() > 0 {
		return AiDiagnosticsHealthCheck{ID: "worker_registered", Status: "pass", Message: "The suggestion queue is configured with workers.", RecommendedActions: []string{}}
	}
	return AiDiagnosticsHealthCheck{ID: "worker_registered", Status: "fail", Message: "The suggestion queue has no configured workers.", RecommendedActions: []string{"Set CCF_AI_QUEUE_WORKERS above zero and restart the worker process."}}
}

func (h *AiDiagnosticsHandler) queueReachableCheck(queue *AiDiagnosticsQueue, queueErr error) AiDiagnosticsHealthCheck {
	if queueErr == nil && queue != nil {
		return AiDiagnosticsHealthCheck{ID: "queue_reachable", Status: "pass", Message: "The River suggestion queue is observable.", RecommendedActions: []string{}}
	}
	message := "The River suggestion queue could not be read."
	if queueErr != nil {
		message = fmt.Sprintf("%s %v", message, queueErr)
	}
	return AiDiagnosticsHealthCheck{ID: "queue_reachable", Status: "warn", Message: message, RecommendedActions: []string{"Verify the River schema has been migrated and the API database user can read river_job."}}
}

func (h *AiDiagnosticsHandler) recentFailureRateCheck(recent recentCellTotals) AiDiagnosticsHealthCheck {
	total := recent.Completed + recent.Failed
	if total == 0 {
		return AiDiagnosticsHealthCheck{ID: "recent_failure_rate", Status: "pass", Message: "No recent completed or failed cells were observed in the last 24 hours.", RecommendedActions: []string{}}
	}
	rate := float64(recent.Failed) / float64(total)
	if rate > 0.2 {
		return AiDiagnosticsHealthCheck{ID: "recent_failure_rate", Status: "warn", Message: fmt.Sprintf("Recent failed cells are %.0f%% of completed or failed cells.", rate*100), RecommendedActions: []string{"Inspect failed run details for provider errors, invalid model output, or input gathering gaps."}}
	}
	return AiDiagnosticsHealthCheck{ID: "recent_failure_rate", Status: "pass", Message: fmt.Sprintf("Recent failed cells are %.0f%% of completed or failed cells.", rate*100), RecommendedActions: []string{}}
}

func (h *AiDiagnosticsHandler) cacheEngagingCheck(totals AiDiagnosticsTotals) AiDiagnosticsHealthCheck {
	if totals.CellsCompleted == 0 {
		return AiDiagnosticsHealthCheck{ID: "cache_engaging", Status: "pass", Message: "No completed cells are available to evaluate prompt caching.", RecommendedActions: []string{}}
	}
	if totals.CacheReadInputTokens > 0 {
		return AiDiagnosticsHealthCheck{ID: "cache_engaging", Status: "pass", Message: "Prompt-cache reads have been observed for completed cells.", RecommendedActions: []string{}}
	}
	if totals.CacheCreationInputTokens == 0 {
		return AiDiagnosticsHealthCheck{
			ID:                 "cache_engaging",
			Status:             "warn",
			Message:            "Completed cells exist, but no prompt-cache writes were observed. Anthropic Haiku requires at least 4,096 input tokens in a cacheable block before caching engages.",
			RecommendedActions: []string{"Inspect prompt sizes for small runs and confirm the selected model supports prompt caching."},
		}
	}
	return AiDiagnosticsHealthCheck{
		ID:                 "cache_engaging",
		Status:             "warn",
		Message:            "Prompt-cache writes have been observed, but no cache reads have been observed yet. Anthropic Haiku requires at least 4,096 input tokens in a cacheable block.",
		RecommendedActions: []string{"Run another dashboard suggestion over overlapping controls to verify cache hits."},
	}
}

func (h *AiDiagnosticsHandler) rateLimitPressureCheck(totals AiDiagnosticsTotals) AiDiagnosticsHealthCheck {
	totalCells := totals.CellsCompleted + totals.CellsFailed
	if totals.RateLimitedTotal == 0 {
		return AiDiagnosticsHealthCheck{ID: "rate_limit_pressure", Status: "pass", Message: "No dashboard suggestion rate-limit snoozes were observed.", RecommendedActions: []string{}}
	}
	if totalCells == 0 {
		if totals.RateLimitedTotal >= 5 {
			return AiDiagnosticsHealthCheck{ID: "rate_limit_pressure", Status: "warn", Message: "Rate-limit snoozes were observed before any cells completed or failed.", RecommendedActions: []string{"Reduce CCF_AI_QUEUE_WORKERS or request higher provider throughput."}}
		}
		return AiDiagnosticsHealthCheck{ID: "rate_limit_pressure", Status: "pass", Message: "Rate-limit snoozes are present but below the warning threshold.", RecommendedActions: []string{}}
	}
	ratio := float64(totals.RateLimitedTotal) / float64(totalCells)
	if totals.RateLimitedTotal >= 5 && ratio > 0.2 {
		return AiDiagnosticsHealthCheck{ID: "rate_limit_pressure", Status: "warn", Message: fmt.Sprintf("Rate-limit snoozes are %.0f%% of completed or failed cells.", ratio*100), RecommendedActions: []string{"Reduce CCF_AI_QUEUE_WORKERS or request higher provider throughput."}}
	}
	return AiDiagnosticsHealthCheck{ID: "rate_limit_pressure", Status: "pass", Message: "Rate-limit snoozes are present but below the warning threshold.", RecommendedActions: []string{}}
}

func (h *AiDiagnosticsHandler) configResponse() AiDiagnosticsConfig {
	cfg := config.DefaultAIConfig()
	if h.cfg != nil {
		cfg = h.cfg
	}
	return AiDiagnosticsConfig{
		Model:                cfg.Model,
		PromptVersion:        suggestionrel.PromptVersion,
		MaxControlsPerChunk:  cfg.MaxControlsPerChunk,
		MaxLabelSetsPerChunk: cfg.MaxLabelSetsPerChunk,
		MaxCallsPerRun:       cfg.MaxCallsPerRun,
		QueueWorkers:         cfg.QueueWorkers,
	}
}

func (h *AiDiagnosticsHandler) aiEnabled() bool {
	return h.cfg != nil && h.cfg.Enabled
}

func (h *AiDiagnosticsHandler) queueWorkers() int {
	if h.cfg != nil && h.cfg.QueueWorkers > 0 {
		return h.cfg.QueueWorkers
	}
	return config.DefaultAIConfig().QueueWorkers
}

func cacheHitRatio(inputTokens int, cacheReadInputTokens int, cacheCreationInputTokens int) float64 {
	denominator := inputTokens + cacheReadInputTokens + cacheCreationInputTokens
	if denominator <= 0 {
		return 0
	}
	return float64(cacheReadInputTokens) / float64(denominator)
}

func durationMs(startedAt *time.Time, completedAt *time.Time) int64 {
	if startedAt == nil || completedAt == nil {
		return 0
	}
	return completedAt.Sub(*startedAt).Milliseconds()
}

func encodeAiDiagnosticsCursor(cursor aiDiagnosticsCursor) string {
	raw, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeAiDiagnosticsCursor(value string) (aiDiagnosticsCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return aiDiagnosticsCursor{}, err
	}
	var cursor aiDiagnosticsCursor
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return aiDiagnosticsCursor{}, err
	}
	if cursor.StartedAt.IsZero() || strings.TrimSpace(cursor.ID) == "" {
		return aiDiagnosticsCursor{}, errors.New("empty cursor")
	}
	return cursor, nil
}
