package oscal

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/compliance-framework/api/internal/service/relational"
	suggestionrel "github.com/compliance-framework/api/internal/service/relational/suggestions"
	workersvc "github.com/compliance-framework/api/internal/service/worker"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrDashboardSuggestionWorkerDisabled = errors.New("dashboard suggestion worker disabled")

type DashboardSuggestionHandler struct {
	sugar       *zap.SugaredLogger
	db          *gorm.DB
	cfg         *config.AIConfig
	jobEnqueuer SSPJobEnqueuer
}

// Request DTOs use kebab-case json tags to match the project convention: the UI
// sends bodies through decamelize-keys (separator "-"), so multi-word fields
// arrive as kebab-case. camelCase tags would silently fail to bind.
type dashboardSuggestionScopeRequest struct {
	ControlKeys    []string `json:"control-keys"`
	LabelSetHashes []string `json:"label-set-hashes"`
	// LabelFilter scopes which evidence (and therefore which label sets) feed the
	// run, using the same label-filter expression as evidence search.
	LabelFilter *labelfilter.Filter `json:"label-filter"`
}

type generateDashboardSuggestionsRequest struct {
	SupersedePending bool                                   `json:"supersede-pending"`
	Scope            *dashboardSuggestionScopeRequest       `json:"scope"`
	Constraints      *dashboardSuggestionConstraintsRequest `json:"constraints"`
}

type labelSelectorRequest struct {
	Key   string  `json:"key"`
	Value *string `json:"value"`
}

type dashboardSuggestionConstraintsRequest struct {
	MandatoryLabels []labelSelectorRequest `json:"mandatory-labels"`
	ExcludedLabels  []labelSelectorRequest `json:"excluded-labels"`
	// OnlyAction restricts suggestions to "new_filter" or "extend_filter".
	OnlyAction string `json:"only-action"`
	// OnlyControlsWithoutFilters scopes generation to controls that currently
	// have no dashboard filter attached. Resolved into the control scope, so it
	// is not persisted as an output constraint.
	OnlyControlsWithoutFilters bool `json:"only-controls-without-filters"`
}

type dashboardSuggestionDecisionRequest struct {
	IDs    []uuid.UUID `json:"ids" validate:"required"`
	Reason string      `json:"reason"`
}

type editDashboardSuggestionGroupRequest struct {
	IDs                []uuid.UUID        `json:"ids" validate:"required"`
	ProposedFilterName *string            `json:"proposed-filter-name"`
	ProposedFilterSet  *map[string]string `json:"proposed-filter-label-set"`
	AddControlKeys     []string           `json:"add-control-keys"`
	RemoveIDs          []uuid.UUID        `json:"remove-ids"`
}

type dashboardSuggestionRunResponse struct {
	suggestionrel.DashboardSuggestionRun
	CompletedCells int `json:"completedCells"`
	FailedCells    int `json:"failedCells"`
}

type dashboardSuggestionResponse struct {
	suggestionrel.DashboardSuggestion
	ControlTitle     string `json:"controlTitle,omitempty"`
	TargetFilterName string `json:"targetFilterName,omitempty"`
}

type controlSuggestionResultResponse struct {
	ControlID        string     `json:"controlId"`
	ControlCatalogID uuid.UUID  `json:"controlCatalogId"`
	Outcome          string     `json:"outcome"`
	SuggestionCount  int        `json:"suggestionCount"`
	RunID            uuid.UUID  `json:"runId"`
	EvaluatedAt      *time.Time `json:"evaluatedAt"`
}

// suggestionEventActor carries the resolved display details for the user that
// triggered a dashboard suggestion event, so the UI can render who acted rather
// than just an opaque user ID.
type suggestionEventActor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type dashboardSuggestionEventResponse struct {
	suggestionrel.DashboardSuggestionEvent
	Actor *suggestionEventActor `json:"actor,omitempty"`
}

type acceptDashboardSuggestionsResponse struct {
	AcceptedFilterIDs []uuid.UUID                   `json:"acceptedFilterIds"`
	Suggestions       []dashboardSuggestionResponse `json:"suggestions"`
}

type dashboardSuggestionConfigResponse struct {
	Enabled bool `json:"enabled"`
}

type dashboardSuggestionPreviewResponse struct {
	PlannedCalls   int  `json:"plannedCalls"`
	ControlCount   int  `json:"controlCount"`
	LabelSetCount  int  `json:"labelSetCount"`
	MaxCallsPerRun int  `json:"maxCallsPerRun"`
	ExceedsLimit   bool `json:"exceedsLimit"`
}

type dashboardSuggestionPlan struct {
	Snapshot      suggestionrel.Snapshot
	PlannedCalls  int
	ControlCount  int
	LabelSetCount int
}

func NewDashboardSuggestionHandler(sugar *zap.SugaredLogger, db *gorm.DB, cfg *config.AIConfig, jobEnqueuer SSPJobEnqueuer) *DashboardSuggestionHandler {
	return &DashboardSuggestionHandler{sugar: sugar, db: db, cfg: cfg, jobEnqueuer: jobEnqueuer}
}

// RegisterConfig mounts the feature-config probe. The caller passes the auth middleware + the
// read guard, so /config sits behind auth like every other route: a valid token identifies the
// subject and the guard enforces dashboard-suggestion:read.
func (h *DashboardSuggestionHandler) RegisterConfig(apiGroup *echo.Group, middlewares ...echo.MiddlewareFunc) {
	apiGroup.GET("/config", h.Config, middlewares...)
}

// Register mounts the SSP-scoped dashboard-suggestion routes. auth is the per-route auth
// middleware; guard enforces the dashboard-suggestion resource. generate/generalize create
// runs; preview and the label/run/list GETs are reads; accept/reject/edit-group mutate
// existing suggestions (update).
func (h *DashboardSuggestionHandler) Register(apiGroup *echo.Group, auth echo.MiddlewareFunc, guard middleware.ResourceGuard) {
	apiGroup.POST("/:id/dashboard-suggestions/generate", h.Generate, auth, guard.Create())
	apiGroup.POST("/:id/dashboard-suggestions/generalize", h.Generalize, auth, guard.Create())
	apiGroup.POST("/:id/dashboard-suggestions/preview", h.Preview, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestions/label-sets", h.LabelSets, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestions/label-keys", h.LabelKeys, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestions/label-values", h.LabelValues, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestion-runs/latest", h.LatestRun, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestion-runs/:runId", h.GetRun, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestions", h.ListSuggestions, auth, guard.Read())
	apiGroup.GET("/:id/dashboard-suggestions/control-results", h.ControlResults, auth, guard.Read())
	apiGroup.POST("/:id/dashboard-suggestions/accept", h.Accept, auth, guard.Update())
	apiGroup.POST("/:id/dashboard-suggestions/reject", h.Reject, auth, guard.Update())
	apiGroup.POST("/:id/dashboard-suggestions/edit-group", h.EditGroup, auth, guard.Update())
	apiGroup.GET("/:id/dashboard-suggestions/:suggestionId/events", h.Events, auth, guard.Read())
}

// Config godoc
//
//	@Summary		Get dashboard suggestions feature configuration
//	@Description	Returns whether AI dashboard suggestions are enabled.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataResponse[oscal.dashboardSuggestionConfigResponse]
//	@Router			/dashboard-suggestions/config [get]
func (h *DashboardSuggestionHandler) Config(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[dashboardSuggestionConfigResponse]{
		Data: dashboardSuggestionConfigResponse{Enabled: h.aiEnabled()},
	})
}

// Generate godoc
//
//	@Summary		Generate dashboard suggestions for an SSP
//	@Description	Creates a dashboard suggestion run, snapshots the resolved scope, creates run cells, and enqueues cell processing.
//	@Tags			Dashboard Suggestions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"System Security Plan ID"
//	@Param			request	body		generateDashboardSuggestionsRequest	false	"Generation request"
//	@Success		202		{object}	handler.GenericDataResponse[oscal.dashboardSuggestionRunResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		503		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/generate [post]
func (h *DashboardSuggestionHandler) Generate(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var req generateDashboardSuggestionsRequest
	if ctx.Request().Body != nil && ctx.Request().ContentLength != 0 {
		if err := ctx.Bind(&req); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
	}
	actorID, err := h.actorUserID(ctx)
	if err != nil {
		return err
	}

	var createdRun suggestionrel.DashboardSuggestionRun
	var cells []suggestionrel.DashboardSuggestionRunCell
	err = h.db.WithContext(ctx.Request().Context()).Transaction(func(tx *gorm.DB) error {
		plan, resolveErr := h.planDashboardSuggestions(tx, sspID, req.Scope, req.Constraints)
		if resolveErr != nil {
			return resolveErr
		}
		snapshot := plan.Snapshot
		plannedCalls := plan.PlannedCalls
		if h.maxCallsPerRun() > 0 && plannedCalls > h.maxCallsPerRun() {
			return &plannedCallsExceededError{Planned: plannedCalls, Limit: h.maxCallsPerRun()}
		}

		runID := uuid.New()
		now := time.Now().UTC()
		createdRun = suggestionrel.DashboardSuggestionRun{
			UUIDModel:         relational.UUIDModel{ID: &runID},
			SSPID:             sspID,
			Status:            "pending",
			Model:             h.modelName(),
			PromptVersion:     suggestionrel.PromptVersion,
			Scope:             snapshotJSON(snapshot),
			Constraints:       suggestionrel.ConstraintsToJSONMap(constraintsFromRequest(req.Constraints)),
			LabelFilter:       suggestionrel.LabelFilterToJSONMap(labelFilterFromRequest(req.Scope)),
			PlannedCalls:      plannedCalls,
			TriggeredByUserID: actorID,
			StartedAt:         &now,
			Stats:             datatypes.JSONMap{},
		}
		if err := tx.Create(&createdRun).Error; err != nil {
			return err
		}
		if req.SupersedePending {
			if err := h.supersedePendingInScope(tx, sspID, runID, actorID, snapshot); err != nil {
				return err
			}
		}
		grid := suggestionrel.BuildGrid(snapshot, h.chunkConfig())
		cells = make([]suggestionrel.DashboardSuggestionRunCell, 0, len(grid))
		for _, cell := range grid {
			cells = append(cells, suggestionrel.DashboardSuggestionRunCell{
				RunID:          runID,
				CellIndex:      cell.CellIndex,
				ControlKeys:    datatypes.NewJSONSlice(cell.ControlKeys),
				LabelSetHashes: datatypes.NewJSONSlice(cell.LabelSetHashes),
				Status:         "pending",
			})
		}
		if len(cells) > 0 {
			if err := tx.Create(&cells).Error; err != nil {
				return err
			}
		}
		if err := createRunEvent(tx, createdRun, suggestionrel.DashboardSuggestionEventTypeRunStarted, actorID, datatypes.JSONMap{
			"planned_calls": plannedCalls,
		}); err != nil {
			return err
		}
		if h.jobEnqueuer == nil {
			return ErrDashboardSuggestionWorkerDisabled
		}
		if err := h.jobEnqueuer.EnqueueDashboardSuggestionCells(ctx.Request().Context(), runID, len(cells)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return h.generateError(ctx, err)
	}

	return ctx.JSON(http.StatusAccepted, handler.GenericDataResponse[dashboardSuggestionRunResponse]{
		Data: dashboardSuggestionRunResponse{DashboardSuggestionRun: createdRun},
	})
}

type generalizeDashboardSuggestionsResponse struct {
	suggestionrel.DashboardSuggestionRun
	Candidates int `json:"candidates"`
	Inserted   int `json:"inserted"`
}

// Generalize godoc
//
//	@Summary		Suggest filter merges for an SSP
//	@Description	Runs the deterministic filter-merge detector for this SSP and creates pending generalization suggestions for near-duplicate filters that differ only by one generalizable label. No LLM is involved.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscal.generalizeDashboardSuggestionsResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/generalize [post]
func (h *DashboardSuggestionHandler) Generalize(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	actorID, err := h.actorUserID(ctx)
	if err != nil {
		return err
	}
	run, result, candidates, err := suggestionrel.NewSuggestionService(h.db.WithContext(ctx.Request().Context())).GenerateGeneralizations(sspID, suggestionrel.GeneralizationRunInput{
		Model:                  h.modelName(),
		PromptVersion:          suggestionrel.PromptVersion,
		GeneralizableLabelKeys: h.generalizableLabelKeys(),
		MinSharedControls:      h.generalizationMinSharedControls(),
		MaxSuggestionsPerRun:   h.maxSuggestionsPerRun(),
		ActorID:                actorID,
	})
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[generalizeDashboardSuggestionsResponse]{
		Data: generalizeDashboardSuggestionsResponse{
			DashboardSuggestionRun: run,
			Candidates:             candidates,
			Inserted:               result.Inserted,
		},
	})
}

// Preview godoc
//
//	@Summary		Preview dashboard suggestion generation for an SSP
//	@Description	Resolves the requested dashboard suggestion scope and returns planned call counts without creating runs or enqueueing work.
//	@Tags			Dashboard Suggestions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"System Security Plan ID"
//	@Param			request	body		generateDashboardSuggestionsRequest	false	"Preview request"
//	@Success		200		{object}	handler.GenericDataResponse[oscal.dashboardSuggestionPreviewResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		422		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/preview [post]
func (h *DashboardSuggestionHandler) Preview(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var req generateDashboardSuggestionsRequest
	if ctx.Request().Body != nil && ctx.Request().ContentLength != 0 {
		if err := ctx.Bind(&req); err != nil {
			return ctx.JSON(http.StatusBadRequest, api.NewError(err))
		}
	}

	plan, err := h.planDashboardSuggestions(h.db.WithContext(ctx.Request().Context()), sspID, req.Scope, req.Constraints)
	if err != nil {
		return h.generateError(ctx, err)
	}
	maxCalls := h.maxCallsPerRun()
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[dashboardSuggestionPreviewResponse]{
		Data: dashboardSuggestionPreviewResponse{
			PlannedCalls:   plan.PlannedCalls,
			ControlCount:   plan.ControlCount,
			LabelSetCount:  plan.LabelSetCount,
			MaxCallsPerRun: maxCalls,
			ExceedsLimit:   maxCalls > 0 && plan.PlannedCalls > maxCalls,
		},
	})
}

// LabelSets godoc
//
//	@Summary		List dashboard suggestion label sets
//	@Description	Returns canonical evidence label sets for dashboard suggestion scope selection.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[suggestions.LabelSetInput]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/label-sets [get]
func (h *DashboardSuggestionHandler) LabelSets(ctx echo.Context) error {
	if _, err := parseUUIDParam(ctx, "id"); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	labelSets, err := suggestionrel.NewSuggestionService(h.db).GatherLabelSets(nil, nil)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[suggestionrel.LabelSetInput]{Data: labelSets})
}

// LabelKeys godoc
//
//	@Summary		List distinct evidence label keys and values
//	@Description	Returns distinct evidence label keys with their distinct values, for building an evidence-scoping filter without loading every label set.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[suggestions.LabelKeyInput]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/label-keys [get]
func (h *DashboardSuggestionHandler) LabelKeys(ctx echo.Context) error {
	if _, err := parseUUIDParam(ctx, "id"); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	keys, err := suggestionrel.NewSuggestionService(h.db).GatherLabelKeys(0)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[suggestionrel.LabelKeyInput]{Data: keys})
}

// LabelValues godoc
//
//	@Summary		Search evidence label values for a key
//	@Description	Returns distinct evidence label values for a given label key, optionally matching a substring query. Searched server-side so high-cardinality values are reachable.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id		path		string	true	"System Security Plan ID"
//	@Param			key		query		string	true	"Label key"
//	@Param			query	query		string	false	"Substring to match against values"
//	@Success		200		{object}	handler.GenericDataListResponse[string]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/label-values [get]
func (h *DashboardSuggestionHandler) LabelValues(ctx echo.Context) error {
	if _, err := parseUUIDParam(ctx, "id"); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	key := strings.TrimSpace(ctx.QueryParam("key"))
	query := strings.TrimSpace(ctx.QueryParam("query"))
	values, err := suggestionrel.NewSuggestionService(h.db).SearchLabelValues(key, query, 50)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[string]{Data: values})
}

// LatestRun godoc
//
//	@Summary		Get latest dashboard suggestion run for an SSP
//	@Description	Returns the latest dashboard suggestion run with cell progress.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataResponse[oscal.dashboardSuggestionRunResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		404	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestion-runs/latest [get]
func (h *DashboardSuggestionHandler) LatestRun(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var run suggestionrel.DashboardSuggestionRun
	if err := h.db.Where("ssp_id = ?", sspID).Order("started_at DESC NULLS LAST").First(&run).Error; err != nil {
		return h.notFoundOrInternal(ctx, err)
	}
	return h.respondRun(ctx, run)
}

// GetRun godoc
//
//	@Summary		Get a dashboard suggestion run
//	@Description	Returns a dashboard suggestion run with cell progress.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id		path		string	true	"System Security Plan ID"
//	@Param			runId	path		string	true	"Dashboard suggestion run ID"
//	@Success		200		{object}	handler.GenericDataResponse[oscal.dashboardSuggestionRunResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		404		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestion-runs/{runId} [get]
func (h *DashboardSuggestionHandler) GetRun(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	runID, err := parseUUIDParam(ctx, "runId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var run suggestionrel.DashboardSuggestionRun
	if err := h.db.Where("id = ? AND ssp_id = ?", runID, sspID).First(&run).Error; err != nil {
		return h.notFoundOrInternal(ctx, err)
	}
	return h.respondRun(ctx, run)
}

// ListSuggestions godoc
//
//	@Summary		List dashboard suggestions for an SSP
//	@Description	Lists dashboard suggestions joined with control title and target filter name.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id		path		string	true	"System Security Plan ID"
//	@Param			status	query		string	false	"Suggestion status (default pending)"
//	@Success		200		{object}	handler.GenericDataListResponse[oscal.dashboardSuggestionResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions [get]
func (h *DashboardSuggestionHandler) ListSuggestions(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	status := strings.TrimSpace(ctx.QueryParam("status"))
	if status == "" {
		status = suggestionrel.DashboardSuggestionStatusPending
	}
	suggestions, err := h.loadSuggestionResponses(h.db.Where("dashboard_suggestions.ssp_id = ? AND dashboard_suggestions.status = ?", sspID, status))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[dashboardSuggestionResponse]{Data: suggestions})
}

// ControlResults godoc
//
//	@Summary		List dashboard suggestion control results for an SSP
//	@Description	Returns the latest dashboard-suggestion evaluation outcome per evaluated control.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id	path		string	true	"System Security Plan ID"
//	@Success		200	{object}	handler.GenericDataListResponse[oscal.controlSuggestionResultResponse]
//	@Failure		400	{object}	api.Error
//	@Failure		401	{object}	api.Error
//	@Failure		500	{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/control-results [get]
func (h *DashboardSuggestionHandler) ControlResults(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var results []controlSuggestionResultResponse
	if err := h.db.WithContext(ctx.Request().Context()).Raw(`
		SELECT DISTINCT ON (control_results.control_catalog_id, control_results.control_id)
			control_results.control_id,
			control_results.control_catalog_id,
			control_results.outcome,
			control_results.suggestion_count,
			control_results.run_id,
			control_results.evaluated_at
		FROM dashboard_suggestion_control_results AS control_results
		JOIN dashboard_suggestion_runs AS runs ON runs.id = control_results.run_id
		WHERE control_results.ssp_id = ?
		ORDER BY control_results.control_catalog_id ASC,
			control_results.control_id ASC,
			runs.started_at DESC NULLS LAST,
			runs.id DESC
	`, sspID).Scan(&results).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[controlSuggestionResultResponse]{Data: results})
}

// Accept godoc
//
//	@Summary		Accept dashboard suggestions
//	@Description	Accepts pending dashboard suggestions and creates or extends SSP-bound filters.
//	@Tags			Dashboard Suggestions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"System Security Plan ID"
//	@Param			request	body		dashboardSuggestionDecisionRequest	true	"Suggestion IDs"
//	@Success		200		{object}	handler.GenericDataResponse[oscal.acceptDashboardSuggestionsResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/accept [post]
func (h *DashboardSuggestionHandler) Accept(ctx echo.Context) error {
	sspID, req, actorID, ok := h.bindDecision(ctx)
	if !ok {
		return nil
	}
	if err := suggestionrel.NewSuggestionService(h.db).Accept(sspID, req.IDs, *actorID); err != nil {
		return h.decisionError(ctx, err)
	}
	suggestions, err := h.loadSuggestionResponses(h.db.Where("dashboard_suggestions.id IN ?", req.IDs))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	accepted := map[uuid.UUID]struct{}{}
	for _, suggestion := range suggestions {
		if suggestion.AcceptedFilterID != nil {
			accepted[*suggestion.AcceptedFilterID] = struct{}{}
		}
	}
	acceptedIDs := make([]uuid.UUID, 0, len(accepted))
	for id := range accepted {
		acceptedIDs = append(acceptedIDs, id)
	}
	sort.Slice(acceptedIDs, func(i, j int) bool { return acceptedIDs[i].String() < acceptedIDs[j].String() })
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[acceptDashboardSuggestionsResponse]{
		Data: acceptDashboardSuggestionsResponse{AcceptedFilterIDs: acceptedIDs, Suggestions: suggestions},
	})
}

// Reject godoc
//
//	@Summary		Reject dashboard suggestions
//	@Description	Rejects pending dashboard suggestions.
//	@Tags			Dashboard Suggestions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"System Security Plan ID"
//	@Param			request	body		dashboardSuggestionDecisionRequest	true	"Suggestion IDs and reason"
//	@Success		200		{object}	handler.GenericDataListResponse[oscal.dashboardSuggestionResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/reject [post]
func (h *DashboardSuggestionHandler) Reject(ctx echo.Context) error {
	sspID, req, actorID, ok := h.bindDecision(ctx)
	if !ok {
		return nil
	}
	if err := suggestionrel.NewSuggestionService(h.db).Reject(sspID, req.IDs, req.Reason, *actorID); err != nil {
		return h.decisionError(ctx, err)
	}
	suggestions, err := h.loadSuggestionResponses(h.db.Where("dashboard_suggestions.id IN ?", req.IDs))
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[dashboardSuggestionResponse]{Data: suggestions})
}

// EditGroup godoc
//
//	@Summary		Edit a group of pending dashboard suggestions
//	@Description	Edits the title, proposed filter labels, and control membership of a pending suggestion group. User-provided labels are stored verbatim (the evidence-subset rule is bypassed) and the rows are flagged as user-edited.
//	@Tags			Dashboard Suggestions
//	@Accept			json
//	@Produce		json
//	@Param			id		path		string								true	"System Security Plan ID"
//	@Param			request	body		editDashboardSuggestionGroupRequest	true	"Group edit"
//	@Success		200		{object}	handler.GenericDataListResponse[oscal.dashboardSuggestionResponse]
//	@Failure		400		{object}	api.Error
//	@Failure		401		{object}	api.Error
//	@Failure		409		{object}	api.Error
//	@Failure		500		{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/edit-group [post]
func (h *DashboardSuggestionHandler) EditGroup(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var req editDashboardSuggestionGroupRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	if len(req.IDs) == 0 {
		return ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("ids is required")))
	}
	actorID, err := h.actorUserID(ctx)
	if err != nil {
		return err
	}

	resultIDs, err := suggestionrel.NewSuggestionService(h.db).EditGroup(sspID, suggestionrel.EditGroupInput{
		IDs:                req.IDs,
		ProposedFilterName: req.ProposedFilterName,
		Labels:             req.ProposedFilterSet,
		AddControlKeys:     req.AddControlKeys,
		RemoveIDs:          req.RemoveIDs,
	}, *actorID)
	if err != nil {
		return h.decisionError(ctx, err)
	}

	suggestions := []dashboardSuggestionResponse{}
	if len(resultIDs) > 0 {
		suggestions, err = h.loadSuggestionResponses(h.db.Where("dashboard_suggestions.id IN ?", resultIDs))
		if err != nil {
			return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
		}
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[dashboardSuggestionResponse]{Data: suggestions})
}

// Events godoc
//
//	@Summary		List dashboard suggestion events
//	@Description	Returns audit events for one dashboard suggestion.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id				path		string	true	"System Security Plan ID"
//	@Param			suggestionId	path		string	true	"Dashboard suggestion ID"
//	@Success		200				{object}	handler.GenericDataListResponse[oscal.dashboardSuggestionEventResponse]
//	@Failure		400				{object}	api.Error
//	@Failure		401				{object}	api.Error
//	@Failure		404				{object}	api.Error
//	@Failure		500				{object}	api.Error
//	@Security		OAuth2Password
//	@Router			/oscal/system-security-plans/{id}/dashboard-suggestions/{suggestionId}/events [get]
func (h *DashboardSuggestionHandler) Events(ctx echo.Context) error {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	suggestionID, err := parseUUIDParam(ctx, "suggestionId")
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	var count int64
	if err := h.db.Model(&suggestionrel.DashboardSuggestion{}).Where("id = ? AND ssp_id = ?", suggestionID, sspID).Count(&count).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	if count == 0 {
		return ctx.JSON(http.StatusNotFound, api.NewError(gorm.ErrRecordNotFound))
	}
	var events []suggestionrel.DashboardSuggestionEvent
	if err := h.db.Where("suggestion_id = ?", suggestionID).Order("occurred_at ASC").Find(&events).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	actors, err := h.resolveEventActors(events)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	responses := make([]dashboardSuggestionEventResponse, 0, len(events))
	for _, event := range events {
		resp := dashboardSuggestionEventResponse{DashboardSuggestionEvent: event}
		if event.ActorUserID != nil {
			if actor, ok := actors[*event.ActorUserID]; ok {
				resp.Actor = &actor
			}
		}
		responses = append(responses, resp)
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[dashboardSuggestionEventResponse]{Data: responses})
}

// resolveEventActors loads the distinct actor users referenced by the given
// events and returns a map keyed by user ID. Users that no longer exist are
// simply omitted from the map.
func (h *DashboardSuggestionHandler) resolveEventActors(events []suggestionrel.DashboardSuggestionEvent) (map[uuid.UUID]suggestionEventActor, error) {
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
		actors[*user.ID] = suggestionEventActor{
			ID:   user.ID.String(),
			Name: handler.UserDisplayName(user),
		}
	}
	return actors, nil
}

func (h *DashboardSuggestionHandler) aiEnabled() bool {
	return h.cfg != nil && h.cfg.Enabled
}

func (h *DashboardSuggestionHandler) chunkConfig() suggestionrel.ChunkConfig {
	if h.cfg == nil {
		return suggestionrel.ChunkConfig{}
	}
	return suggestionrel.ChunkConfig{MaxControlsPerChunk: h.cfg.MaxControlsPerChunk, MaxLabelSetsPerChunk: h.cfg.MaxLabelSetsPerChunk}
}

func (h *DashboardSuggestionHandler) maxCallsPerRun() int {
	if h.cfg == nil {
		return 0
	}
	return h.cfg.MaxCallsPerRun
}

func (h *DashboardSuggestionHandler) maxSuggestionsPerRun() int {
	if h.cfg == nil {
		return 0
	}
	return h.cfg.MaxSuggestionsPerRun
}

func (h *DashboardSuggestionHandler) generalizableLabelKeys() []string {
	if h.cfg == nil {
		return nil
	}
	return h.cfg.GeneralizableLabelKeys
}

func (h *DashboardSuggestionHandler) generalizationMinSharedControls() int {
	if h.cfg == nil {
		return 0
	}
	return h.cfg.GeneralizationMinSharedControls
}

func (h *DashboardSuggestionHandler) modelName() string {
	if h.cfg == nil || strings.TrimSpace(h.cfg.Model) == "" {
		return config.DefaultAIModel
	}
	return h.cfg.Model
}

func (h *DashboardSuggestionHandler) planDashboardSuggestions(db *gorm.DB, sspID uuid.UUID, scope *dashboardSuggestionScopeRequest, constraints *dashboardSuggestionConstraintsRequest) (dashboardSuggestionPlan, error) {
	svc := suggestionrel.NewSuggestionService(db)
	snapshot, err := svc.ResolveScope(sspID, scopeFromRequest(scope))
	if err != nil {
		return dashboardSuggestionPlan{}, err
	}
	if constraints != nil && constraints.OnlyControlsWithoutFilters {
		filtered, err := svc.ControlKeysWithoutFilters(sspID, snapshot.ControlKeys)
		if err != nil {
			return dashboardSuggestionPlan{}, err
		}
		snapshot.ControlKeys = filtered
	}
	if len(snapshot.ControlKeys) == 0 {
		return dashboardSuggestionPlan{}, &emptyDashboardSuggestionScopeError{message: "no controls resolved for dashboard suggestions"}
	}
	if len(snapshot.LabelSetHashes) == 0 {
		return dashboardSuggestionPlan{}, &emptyDashboardSuggestionScopeError{message: "no evidence label sets resolved for dashboard suggestions"}
	}
	return dashboardSuggestionPlan{
		Snapshot:      snapshot,
		PlannedCalls:  suggestionrel.PlannedCalls(len(snapshot.ControlKeys), len(snapshot.LabelSetHashes), h.chunkConfig()),
		ControlCount:  len(snapshot.ControlKeys),
		LabelSetCount: len(snapshot.LabelSetHashes),
	}, nil
}

func scopeFromRequest(scope *dashboardSuggestionScopeRequest) suggestionrel.Scope {
	if scope == nil {
		return suggestionrel.Scope{}
	}
	return suggestionrel.Scope{
		ControlKeys:    scope.ControlKeys,
		LabelSetHashes: scope.LabelSetHashes,
		LabelFilter:    scope.LabelFilter,
	}
}

func labelFilterFromRequest(scope *dashboardSuggestionScopeRequest) *labelfilter.Filter {
	if scope == nil {
		return nil
	}
	return scope.LabelFilter
}

func constraintsFromRequest(constraints *dashboardSuggestionConstraintsRequest) suggestionrel.Constraints {
	if constraints == nil {
		return suggestionrel.Constraints{}
	}
	return suggestionrel.Constraints{
		MandatoryLabels: labelSelectorsFromRequest(constraints.MandatoryLabels),
		ExcludedLabels:  labelSelectorsFromRequest(constraints.ExcludedLabels),
		OnlyAction:      constraints.OnlyAction,
	}.Normalize()
}

func labelSelectorsFromRequest(selectors []labelSelectorRequest) []suggestionrel.LabelSelector {
	if len(selectors) == 0 {
		return nil
	}
	out := make([]suggestionrel.LabelSelector, 0, len(selectors))
	for _, selector := range selectors {
		out = append(out, suggestionrel.LabelSelector{Key: selector.Key, Value: selector.Value})
	}
	return out
}

func snapshotJSON(snapshot suggestionrel.Snapshot) datatypes.JSONMap {
	return datatypes.JSONMap{
		"controlKeys":    append([]string(nil), snapshot.ControlKeys...),
		"labelSetHashes": append([]string(nil), snapshot.LabelSetHashes...),
	}
}

func parseUUIDParam(ctx echo.Context, name string) (uuid.UUID, error) {
	return uuid.Parse(ctx.Param(name))
}

func (h *DashboardSuggestionHandler) actorUserID(ctx echo.Context) (*uuid.UUID, error) {
	claims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || claims == nil {
		return nil, ctx.JSON(http.StatusUnauthorized, api.NewError(fmt.Errorf("missing authentication claims")))
	}
	var user relational.User
	if err := h.db.Where("email = ?", claims.Subject).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("user not found")))
		}
		return nil, ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return user.ID, nil
}

func (h *DashboardSuggestionHandler) bindDecision(ctx echo.Context) (uuid.UUID, dashboardSuggestionDecisionRequest, *uuid.UUID, bool) {
	sspID, err := parseUUIDParam(ctx, "id")
	if err != nil {
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return uuid.Nil, dashboardSuggestionDecisionRequest{}, nil, false
	}
	var req dashboardSuggestionDecisionRequest
	if err := ctx.Bind(&req); err != nil {
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(err))
		return uuid.Nil, dashboardSuggestionDecisionRequest{}, nil, false
	}
	if len(req.IDs) == 0 {
		_ = ctx.JSON(http.StatusBadRequest, api.NewError(fmt.Errorf("ids is required")))
		return uuid.Nil, dashboardSuggestionDecisionRequest{}, nil, false
	}
	actorID, err := h.actorUserID(ctx)
	if err != nil {
		return uuid.Nil, dashboardSuggestionDecisionRequest{}, nil, false
	}
	return sspID, req, actorID, true
}

func (h *DashboardSuggestionHandler) supersedePendingInScope(tx *gorm.DB, sspID, newRunID uuid.UUID, actorID *uuid.UUID, snapshot suggestionrel.Snapshot) error {
	query := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("ssp_id = ? AND status = ?", sspID, suggestionrel.DashboardSuggestionStatusPending)
	if len(snapshot.LabelSetHashes) > 0 {
		query = query.Where("label_set_hash IN ?", snapshot.LabelSetHashes)
	}
	controlFilter := tx.Session(&gorm.Session{})
	for idx, key := range snapshot.ControlKeys {
		catalogID, controlID, err := suggestionrel.ParseControlKey(key)
		if err != nil {
			return err
		}
		condition := tx.Where("control_catalog_id = ? AND control_id = ?", catalogID, controlID)
		if idx == 0 {
			controlFilter = controlFilter.Where(condition)
		} else {
			controlFilter = controlFilter.Or(condition)
		}
	}
	if len(snapshot.ControlKeys) > 0 {
		query = query.Where(controlFilter)
	}

	var suggestions []suggestionrel.DashboardSuggestion
	if err := query.Find(&suggestions).Error; err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, suggestion := range suggestions {
		if err := tx.Model(&suggestionrel.DashboardSuggestion{}).
			Where("id = ?", suggestion.ID).
			Updates(map[string]any{
				"status":             suggestionrel.DashboardSuggestionStatusSuperseded,
				"decided_by_user_id": actorID,
				"decided_at":         now,
			}).Error; err != nil {
			return err
		}
		suggestion.Status = suggestionrel.DashboardSuggestionStatusSuperseded
		suggestion.DecidedByUserID = actorID
		suggestion.DecidedAt = &now
		if err := createSuggestionAuditEvent(tx, suggestion, suggestionrel.DashboardSuggestionEventTypeSuperseded, actorID, datatypes.JSONMap{
			"new_run_id": newRunID.String(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func createRunEvent(tx *gorm.DB, run suggestionrel.DashboardSuggestionRun, eventType suggestionrel.DashboardSuggestionEventType, actorID *uuid.UUID, payload datatypes.JSONMap) error {
	snapshot, err := jsonMapFrom(run)
	if err != nil {
		return err
	}
	event := suggestionrel.DashboardSuggestionEvent{
		RunID:       run.ID,
		EventType:   string(eventType),
		ActorUserID: actorID,
		OccurredAt:  time.Now().UTC(),
		Payload:     payload,
		Snapshot:    snapshot,
	}
	return tx.Create(&event).Error
}

func createSuggestionAuditEvent(tx *gorm.DB, suggestion suggestionrel.DashboardSuggestion, eventType suggestionrel.DashboardSuggestionEventType, actorID *uuid.UUID, payload datatypes.JSONMap) error {
	snapshot, err := jsonMapFrom(suggestion)
	if err != nil {
		return err
	}
	event := suggestionrel.DashboardSuggestionEvent{
		RunID:        &suggestion.RunID,
		SuggestionID: suggestion.ID,
		EventType:    string(eventType),
		ActorUserID:  actorID,
		OccurredAt:   time.Now().UTC(),
		Payload:      payload,
		Snapshot:     snapshot,
	}
	return tx.Create(&event).Error
}

func jsonMapFrom(value any) (datatypes.JSONMap, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out datatypes.JSONMap
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *DashboardSuggestionHandler) respondRun(ctx echo.Context, run suggestionrel.DashboardSuggestionRun) error {
	completed, failed, err := h.cellProgress(*run.ID)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[dashboardSuggestionRunResponse]{
		Data: dashboardSuggestionRunResponse{DashboardSuggestionRun: run, CompletedCells: completed, FailedCells: failed},
	})
}

func (h *DashboardSuggestionHandler) cellProgress(runID uuid.UUID) (int, int, error) {
	var rows []struct {
		Status string
		Count  int
	}
	if err := h.db.Model(&suggestionrel.DashboardSuggestionRunCell{}).
		Select("status, count(*) as count").
		Where("run_id = ?", runID).
		Group("status").
		Scan(&rows).Error; err != nil {
		return 0, 0, err
	}
	completed := 0
	failed := 0
	for _, row := range rows {
		switch row.Status {
		case "completed":
			completed = row.Count
		case "failed":
			failed = row.Count
		}
	}
	return completed, failed, nil
}

func (h *DashboardSuggestionHandler) loadSuggestionResponses(query *gorm.DB) ([]dashboardSuggestionResponse, error) {
	type row struct {
		suggestionrel.DashboardSuggestion
		ControlTitle     *string `gorm:"column:control_title"`
		TargetFilterName *string `gorm:"column:target_filter_name"`
	}
	var rows []row
	if err := query.
		Model(&suggestionrel.DashboardSuggestion{}).
		Select("dashboard_suggestions.*, controls.title AS control_title, filters.name AS target_filter_name").
		Joins("LEFT JOIN controls ON controls.catalog_id = dashboard_suggestions.control_catalog_id AND controls.id = dashboard_suggestions.control_id").
		Joins("LEFT JOIN filters ON filters.id = dashboard_suggestions.target_filter_id").
		Order("dashboard_suggestions.control_id ASC, dashboard_suggestions.proposed_filter_name ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]dashboardSuggestionResponse, 0, len(rows))
	for _, row := range rows {
		item := dashboardSuggestionResponse{DashboardSuggestion: row.DashboardSuggestion}
		if row.ControlTitle != nil {
			item.ControlTitle = *row.ControlTitle
		}
		if row.TargetFilterName != nil {
			item.TargetFilterName = *row.TargetFilterName
		}
		out = append(out, item)
	}
	return out, nil
}

type plannedCallsExceededError struct {
	Planned int
	Limit   int
}

func (e *plannedCallsExceededError) Error() string {
	return fmt.Sprintf("planned calls %d exceeds limit %d", e.Planned, e.Limit)
}

type emptyDashboardSuggestionScopeError struct {
	message string
}

func (e *emptyDashboardSuggestionScopeError) Error() string {
	return e.message
}

func (h *DashboardSuggestionHandler) generateError(ctx echo.Context, err error) error {
	var scopeErr *suggestionrel.ScopeError
	if errors.As(err, &scopeErr) {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}
	var emptyScopeErr *emptyDashboardSuggestionScopeError
	if errors.As(err, &emptyScopeErr) {
		return ctx.JSON(http.StatusUnprocessableEntity, api.NewError(err))
	}
	var plannedErr *plannedCallsExceededError
	if errors.As(err, &plannedErr) {
		return ctx.JSON(http.StatusUnprocessableEntity, api.Error{Errors: map[string]any{
			"body":         plannedErr.Error(),
			"plannedCalls": plannedErr.Planned,
			"limit":        plannedErr.Limit,
		}})
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ctx.JSON(http.StatusConflict, api.NewError(fmt.Errorf("active dashboard suggestion run already exists")))
	}
	if errors.Is(err, ErrDashboardSuggestionWorkerDisabled) ||
		errors.Is(err, workersvc.ErrDashboardSuggestionWorkerDisabled) ||
		strings.Contains(strings.ToLower(err.Error()), "worker service is disabled") {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(ErrDashboardSuggestionWorkerDisabled))
	}
	if errors.Is(err, workersvc.ErrDashboardSuggestionWorkerNotRegistered) {
		return ctx.JSON(http.StatusServiceUnavailable, api.NewError(workersvc.ErrDashboardSuggestionWorkerNotRegistered))
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
}

func (h *DashboardSuggestionHandler) decisionError(ctx echo.Context, err error) error {
	var conflict *suggestionrel.ConflictError
	if errors.As(err, &conflict) {
		return ctx.JSON(http.StatusConflict, api.NewError(err))
	}
	var editErr *suggestionrel.EditValidationError
	if errors.As(err, &editErr) {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
}

func (h *DashboardSuggestionHandler) notFoundOrInternal(ctx echo.Context, err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
}
