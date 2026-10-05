package handler

import (
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type HeartbeatHandler struct {
	db        *gorm.DB
	sugar     *zap.SugaredLogger
	instances *agentcfg.Service
}

func NewHeartbeatHandler(sugar *zap.SugaredLogger, db *gorm.DB) *HeartbeatHandler {
	return &HeartbeatHandler{
		sugar: sugar,
		db:    db,
	}
}

// WithAgentInstances makes authenticated heartbeats update the agent-instance registry
// (R11): last-seen always, and a new instance row only when the heartbeat carries a config
// digest.
func (h *HeartbeatHandler) WithAgentInstances(svc *agentcfg.Service) *HeartbeatHandler {
	h.instances = svc
	return h
}

func (h *HeartbeatHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("/over-time", h.OverTime)
}

func (h *HeartbeatHandler) RegisterCreate(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.POST("", h.Create, middlewares...)
}

func (h *HeartbeatHandler) RegisterOverTime(api *echo.Group, middlewares ...echo.MiddlewareFunc) {
	api.GET("/over-time", h.OverTime, middlewares...)
}

type HeartbeatCreateRequest struct {
	// UUID is the agent instance id.
	UUID      uuid.UUID `json:"uuid,omitempty" validate:"required"`
	CreatedAt time.Time `json:"created_at,omitempty" validate:"required"`
	// ConfigRevision is the APPLIED configuration revision, 0 when running from the file only
	// (R45). Absent for old agents and mode off.
	ConfigRevision *int64 `json:"config_revision,omitempty"`
	// ConfigDigest is agentconfig.Digest of the effective config; sent whenever mode != off.
	ConfigDigest *string `json:"config_digest,omitempty"`
}

// Create godoc
//
//	@Summary		Create Heartbeat
//	@Description	Creates a new heartbeat record for monitoring. An authenticated agent heartbeat also refreshes the instance's last-seen time; with config_digest (new agents, mode != off) it records config_revision/config_digest and registers the instance if needed. That registration is authorized by heartbeat:ingest, not agent:sync: removing sync from an agent's role stops overlay fetches and config reports, not instance registration by heartbeats.
//	@Tags			Heartbeat
//	@Accept			json
//	@Produce		json
//	@Param			heartbeat	body	HeartbeatCreateRequest	true	"Heartbeat payload"
//	@Success		201			"Created"
//	@Failure		400			{object}	api.Error
//	@Failure		500			{object}	api.Error
//	@Router			/agent/heartbeat [post]
func (h *HeartbeatHandler) Create(ctx echo.Context) error {
	// Bind the incoming JSON payload into a slice of SDK findings.
	var heartbeat HeartbeatCreateRequest
	if err := ctx.Bind(&heartbeat); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	err := ctx.Validate(heartbeat)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, api.Validator(err))
	}

	if err := h.db.Create(&service.Heartbeat{
		UUID:      heartbeat.UUID,
		CreatedAt: heartbeat.CreatedAt,
	}).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	h.touchAgentInstance(ctx, heartbeat)

	// Return a 201 Created response with no content.
	return ctx.NoContent(http.StatusCreated)
}

// touchAgentInstance records an authenticated heartbeat against the agent-instance registry.
// Failures are logged and never change the 201; anonymous heartbeats are ignored.
func (h *HeartbeatHandler) touchAgentInstance(ctx echo.Context, heartbeat HeartbeatCreateRequest) {
	if h.instances == nil {
		return
	}
	auth := agentAuthFrom(ctx)
	if auth == nil {
		return
	}
	var credentialID *uuid.UUID
	if auth.Key != nil && auth.Key.ID != nil {
		id := *auth.Key.ID
		credentialID = &id
	}
	// Only a well-formed digest may register an instance; anything else is treated as absent
	// (last-seen update only).
	digest := heartbeat.ConfigDigest
	if digest != nil && !effectiveDigestPattern.MatchString(*digest) {
		digest = nil
	}
	revision := heartbeat.ConfigRevision
	if revision != nil && *revision < 0 {
		revision = nil
	}
	if err := h.instances.TouchFromHeartbeat(ctx.Request().Context(), *auth.Agent.ID, credentialID, heartbeat.UUID, revision, digest); err != nil {
		h.sugar.Warnw("Failed to record agent heartbeat against its instance",
			"agentID", *auth.Agent.ID, "instanceID", heartbeat.UUID, "error", err)
	}
}

// OverTime godoc
//
//	@Summary		Get Heartbeat Metrics Over Time
//	@Description	Retrieves heartbeat counts aggregated by 2-minute intervals.
//	@Tags			Heartbeat
//	@Produce		json
//	@Success		200	{object}	handler.GenericDataListResponse[handler.OverTime.HeartbeatInterval]
//	@Failure		500	{object}	api.Error
//	@Router			/agent/heartbeat/over-time [get]
func (h *HeartbeatHandler) OverTime(ctx echo.Context) error {

	type HeartbeatInterval struct {
		Interval time.Time `json:"interval"`
		Total    int64     `json:"total"`
	}

	var results []HeartbeatInterval
	if err := h.db.Raw(`
		select count(*) as total, "interval"
		from (
			select distinct on (uuid, date_bin('2 min', created_at, now())) uuid, date_bin('2 min', created_at, now()) as "interval"
			from heartbeats
			order by date_bin('2 min', created_at, now())
		) as heartbeat_intervalled
		group by "interval"
	`).Scan(&results).Error; err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the result in GenericDataResponse.
	return ctx.JSON(http.StatusOK, GenericDataListResponse[HeartbeatInterval]{
		Data: results,
	})
}
