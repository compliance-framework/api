package handler

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/service"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"net/http"
	"time"
)

type HeartbeatHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

func NewHeartbeatHandler(sugar *zap.SugaredLogger, db *gorm.DB) *HeartbeatHandler {
	return &HeartbeatHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *HeartbeatHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("/over-time", h.OverTime)
}

type HeartbeatCreateRequest struct {
	UUID      uuid.UUID `json:"uuid,omitempty" validate:"required"`
	CreatedAt time.Time `json:"created_at,omitempty" validate:"required"`
}

// Create godoc
//
//	@Summary		Create Heartbeat
//	@Description	Creates a new heartbeat record for monitoring.
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

	// Return a 201 Created response with no content.
	return ctx.NoContent(http.StatusCreated)
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
