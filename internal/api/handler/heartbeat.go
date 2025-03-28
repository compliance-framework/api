package handler

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"net/http"
)

type HeartbeatHandler struct {
	heartbeatService *service.HeartbeatService
	sugar            *zap.SugaredLogger
}

func (h *HeartbeatHandler) Register(api *echo.Group) {
	api.POST("", h.Create)
	api.GET("/over-time", h.OverTime)
}

func NewHeartbeatHandler(
	l *zap.SugaredLogger,
	heartbeatService *service.HeartbeatService,
) *HeartbeatHandler {
	return &HeartbeatHandler{
		sugar:            l,
		heartbeatService: heartbeatService,
	}
}

// Create purposefully has no swagger doc to prevent it showing up in the swagger ui. This is for internal use only.
func (h *HeartbeatHandler) Create(ctx echo.Context) error {
	// Bind the incoming JSON payload into a slice of SDK findings.
	var heartbeat *service.Heartbeat
	if err := ctx.Bind(&heartbeat); err != nil {
		return ctx.JSON(http.StatusBadRequest, api.NewError(err))
	}

	_, err := h.heartbeatService.Create(ctx.Request().Context(), heartbeat)

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Return a 201 Created response with no content.
	return ctx.NoContent(http.StatusCreated)
}

// OverTime purposefully has no swagger doc to prevent it showing up in the swagger ui. This is for internal use only.
func (h *HeartbeatHandler) OverTime(ctx echo.Context) error {
	// Bind the incoming JSON payload into a slice of SDK findings.
	results, err := h.heartbeatService.GetIntervalledHeartbeats(ctx.Request().Context())

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	// Wrap the result in GenericDataResponse.
	return ctx.JSON(http.StatusOK, GenericDataListResponse[service.HeartbeatOverTimeGroup]{
		Data: results,
	})
}
