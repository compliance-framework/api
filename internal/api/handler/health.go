package handler

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/compliance-framework/api/internal/authz"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// pdpHealthTimeout bounds the PDP readiness probe so a hung PDP can't stall /health/ready.
const pdpHealthTimeout = 2 * time.Second

type HealthHandler struct {
	db    *gorm.DB
	pdp   authz.PDP
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

// WithPDP attaches the authorization PDP so readiness reflects the decision engine's
// availability (a remote AuthZen PDP being down makes the API not-ready). Returns the
// handler for chaining. The in-process builtin driver doesn't implement Healther, so it
// is treated as always healthy.
func (h *HealthHandler) WithPDP(pdp authz.PDP) *HealthHandler {
	h.pdp = pdp
	return h
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

	if checker, ok := h.pdp.(authz.Healther); ok {
		hctx, cancel := context.WithTimeout(ctx.Request().Context(), pdpHealthTimeout)
		defer cancel()
		if err := checker.Health(hctx); err != nil {
			h.sugar.Errorw("authz PDP health check failed", "err", err)
			return ctx.JSON(http.StatusServiceUnavailable, healthResponse{Status: "unavailable"})
		}
	}

	return ctx.JSON(http.StatusOK, healthResponse{Status: "ok"})
}

func (h *HealthHandler) sqlDB() (*sql.DB, error) {
	if h.db == nil {
		return nil, sql.ErrConnDone
	}

	return h.db.DB()
}
