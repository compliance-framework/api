package middleware

import (
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RequireAdminGroups enforces that SSO-authenticated users belong to the provider's
// configured admin groups. Password-based logins bypass this check (treated as super
// admins).
//
// It is now a thin PEP over the builtin authz driver: the enforcement rule lives in
// authz.Builtin so it has a single home and can be served by other drivers in later
// phases, while the access decision is unchanged. Callers keep the same signature.
func RequireAdminGroups(db *gorm.DB, cfg *config.Config, logger *zap.SugaredLogger) echo.MiddlewareFunc {
	failMode := authz.FailClosed
	if cfg != nil && cfg.Authz != nil {
		failMode = authz.ParseFailMode(cfg.Authz.FailMode)
	}
	// Phase 1 hard-wires admin enforcement to the builtin driver, whereas the evidence PEP
	// in api.go uses the config-selected driver via authz.Open. These are identical while
	// builtin is the only/default driver; they diverge once a second driver is configured
	// (admin would stay on builtin). A middleware constructor can't return an error to honor
	// an arbitrary driver — route admin through authz.Open when a real second driver lands.
	pep := NewPEP(authz.NewBuiltin(db, cfg, logger), failMode, logger)
	return pep.Authorize(authz.ResourceAdmin, authz.ActionManage)
}
