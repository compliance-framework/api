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
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
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

type dashboardSuggestionScopeRequest struct {
	ControlKeys    []string `json:"controlKeys"`
	LabelSetHashes []string `json:"labelSetHashes"`
}

type generateDashboardSuggestionsRequest struct {
	SupersedePending bool                             `json:"supersedePending"`
	Scope            *dashboardSuggestionScopeRequest `json:"scope"`
}

type dashboardSuggestionDecisionRequest struct {
	IDs    []uuid.UUID `json:"ids" validate:"required"`
	Reason string      `json:"reason"`
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

type acceptDashboardSuggestionsResponse struct {
	AcceptedFilterIDs []uuid.UUID                   `json:"acceptedFilterIds"`
	Suggestions       []dashboardSuggestionResponse `json:"suggestions"`
}

type dashboardSuggestionConfigResponse struct {
	Enabled bool `json:"enabled"`
}

func NewDashboardSuggestionHandler(sugar *zap.SugaredLogger, db *gorm.DB, cfg *config.AIConfig, jobEnqueuer SSPJobEnqueuer) *DashboardSuggestionHandler {
	return &DashboardSuggestionHandler{sugar: sugar, db: db, cfg: cfg, jobEnqueuer: jobEnqueuer}
}

func (h *DashboardSuggestionHandler) RegisterConfig(apiGroup *echo.Group) {
	apiGroup.GET("/config", h.Config)
}

func (h *DashboardSuggestionHandler) Register(apiGroup *echo.Group, auth echo.MiddlewareFunc) {
	apiGroup.POST("/:id/dashboard-suggestions/generate", h.Generate, auth)
	apiGroup.GET("/:id/dashboard-suggestions/label-sets", h.LabelSets, auth)
	apiGroup.GET("/:id/dashboard-suggestion-runs/latest", h.LatestRun, auth)
	apiGroup.GET("/:id/dashboard-suggestion-runs/:runId", h.GetRun, auth)
	apiGroup.GET("/:id/dashboard-suggestions", h.ListSuggestions, auth)
	apiGroup.POST("/:id/dashboard-suggestions/accept", h.Accept, auth)
	apiGroup.POST("/:id/dashboard-suggestions/reject", h.Reject, auth)
	apiGroup.GET("/:id/dashboard-suggestions/:suggestionId/events", h.Events, auth)
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
		svc := suggestionrel.NewSuggestionService(tx)
		snapshot, resolveErr := svc.ResolveScope(sspID, scopeFromRequest(req.Scope))
		if resolveErr != nil {
			return resolveErr
		}
		if len(snapshot.ControlKeys) == 0 {
			return &emptyDashboardSuggestionScopeError{message: "no controls resolved for dashboard suggestions"}
		}
		if len(snapshot.LabelSetHashes) == 0 {
			return &emptyDashboardSuggestionScopeError{message: "no evidence label sets resolved for dashboard suggestions"}
		}
		plannedCalls := suggestionrel.PlannedCalls(len(snapshot.ControlKeys), len(snapshot.LabelSetHashes), h.chunkConfig())
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
	labelSets, err := suggestionrel.NewSuggestionService(h.db).GatherLabelSets(nil)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[suggestionrel.LabelSetInput]{Data: labelSets})
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

// Events godoc
//
//	@Summary		List dashboard suggestion events
//	@Description	Returns audit events for one dashboard suggestion.
//	@Tags			Dashboard Suggestions
//	@Produce		json
//	@Param			id				path		string	true	"System Security Plan ID"
//	@Param			suggestionId	path		string	true	"Dashboard suggestion ID"
//	@Success		200				{object}	handler.GenericDataListResponse[suggestions.DashboardSuggestionEvent]
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
	return ctx.JSON(http.StatusOK, handler.GenericDataListResponse[suggestionrel.DashboardSuggestionEvent]{Data: events})
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

func (h *DashboardSuggestionHandler) modelName() string {
	if h.cfg == nil || strings.TrimSpace(h.cfg.Model) == "" {
		return config.DefaultAIModel
	}
	return h.cfg.Model
}

func scopeFromRequest(scope *dashboardSuggestionScopeRequest) suggestionrel.Scope {
	if scope == nil {
		return suggestionrel.Scope{}
	}
	return suggestionrel.Scope{ControlKeys: scope.ControlKeys, LabelSetHashes: scope.LabelSetHashes}
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
	if errors.Is(err, ErrDashboardSuggestionWorkerDisabled) || strings.Contains(strings.ToLower(err.Error()), "worker service is disabled") {
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
	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
}

func (h *DashboardSuggestionHandler) notFoundOrInternal(ctx echo.Context, err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ctx.JSON(http.StatusNotFound, api.NewError(err))
	}
	return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
}
