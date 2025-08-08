package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type HealthHandler struct {
	logger *zap.SugaredLogger
	db     *gorm.DB
}

func NewHealthHandler(logger *zap.SugaredLogger, db *gorm.DB) *HealthHandler {
	return &HealthHandler{
		logger: logger,
		db:     db,
	}
}

func (h *HealthHandler) Register(api *echo.Group) {
	api.GET("", h.Health)
	api.GET("/ready", h.Ready)
}

// Health godoc
//
//	@Summary		Health check
//	@Description	Returns health status of the API
//	@Tags			health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]string
//	@Router			/health [get]
func (h *HealthHandler) Health(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

// Ready godoc
//
//	@Summary		Readiness check
//	@Description	Returns readiness status of the API including database connectivity
//	@Tags			health
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	map[string]interface{}
//	@Failure		503	{object}	map[string]interface{}
//	@Router			/health/ready [get]
func (h *HealthHandler) Ready(ctx echo.Context) error {
	// Check database connection
	sqlDB, err := h.db.DB()
	if err != nil {
		return ctx.JSON(http.StatusServiceUnavailable, map[string]interface{}{
			"status": "not ready",
			"error":  "database connection error",
		})
	}

	if err := sqlDB.Ping(); err != nil {
		return ctx.JSON(http.StatusServiceUnavailable, map[string]interface{}{
			"status": "not ready",
			"error":  "database ping failed",
		})
	}

	return ctx.JSON(http.StatusOK, map[string]interface{}{
		"status": "ready",
		"database": "connected",
	})
}