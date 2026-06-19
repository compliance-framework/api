package middleware

import (
	"github.com/compliance-framework/api/internal/authz"
	"github.com/compliance-framework/api/internal/config"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RequireAdminGroups enforces that SSO-authenticated users belong to the provider's configured
// admin groups. Password-based logins bypass this middleware (treated as super admins).
//
// It is now a thin wrapper over the central authorization PEP: it builds an
// Authorizer for the configured driver and enforces the "admin" resource. The
// builtin driver reproduces this exact rule (see internal/authz). New routes
// should construct one Authorizer via NewAuthorizerFromConfig and call
// Authorize("admin", ...) directly rather than using this helper.
func RequireAdminGroups(db *gorm.DB, cfg *config.Config, logger *zap.SugaredLogger) echo.MiddlewareFunc {
	return NewAuthorizerFromConfig(db, cfg, logger).Authorize(authz.ResourceAdmin, "manage")
}
