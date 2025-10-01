package handler

import (
	"database/sql"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type HealthHandler struct {
	db    *gorm.DB
	sugar *zap.SugaredLogger
}

type healthResponse struct {
	Status string `json:"status"`
}

func NewHealthHandler(sugar *zap.SugaredLogger, db *gorm.DB) *HealthHandler {
	return &HealthHandler{
		sugar: sugar,
		db:    db,
	}
}

func (h *HealthHandler) Register(api *echo.Group) {
	api.GET("", h.Health)
	api.GET("/ready", h.Ready)
}

func (h *HealthHandler) Health(ctx echo.Context) error {
	return ctx.JSON(http.StatusOK, healthResponse{Status: "ok"})
}

func (h *HealthHandler) Ready(ctx echo.Context) error {
	sqlDB, err := h.sqlDB()
	if err != nil {
		h.sugar.Errorw("failed to retrieve sql DB", "err", err)
		return ctx.JSON(http.StatusServiceUnavailable, healthResponse{Status: "unavailable"})
	}

	if err := sqlDB.PingContext(ctx.Request().Context()); err != nil {
		h.sugar.Errorw("database ping failed", "err", err)
		return ctx.JSON(http.StatusServiceUnavailable, healthResponse{Status: "unavailable"})
	}

	return ctx.JSON(http.StatusOK, healthResponse{Status: "ok"})
}

func (h *HealthHandler) sqlDB() (*sql.DB, error) {
	if h.db == nil {
		return nil, sql.ErrConnDone
	}

	return h.db.DB()
}
