package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RequireAdminGroups enforces that SSO-authenticated users belong to the provider's configured
// admin groups. Password-based logins bypass this middleware (treated as super admins).
func RequireAdminGroups(db *gorm.DB, cfg *config.Config, logger *zap.SugaredLogger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get("user").(*authn.UserClaims)
			if !ok || claims == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "missing authentication claims")
			}

			var user relational.User
			if err := db.Where("email = ?", claims.Subject).First(&user).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return echo.NewHTTPError(http.StatusForbidden, "user not found")
				}
				logger.Errorw("Failed to load user for admin enforcement", "email", claims.Subject, "error", err)
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to load user")
			}

			if strings.ToLower(user.AuthMethod) != "sso" {
				// Password (or other non-SSO) users bypass group enforcement.
				return next(c)
			}
			if cfg == nil || cfg.SSO == nil || !cfg.SSO.Enabled {
				// Without SSO config we cannot enforce provider-based admin groups; allow request.
				return next(c)
			}

			var link relational.SSOUserLink
			if err := db.
				Where("user_id = ? AND deleted_at IS NULL", user.ID.String()).
				Order("last_sync DESC").
				First(&link).Error; err != nil {
				logger.Warnw("Missing SSO link for admin enforcement", "userID", user.ID.String(), "error", err)
				return echo.NewHTTPError(http.StatusForbidden, "missing SSO link for user")
			}

			providerConfig := cfg.SSO.GetProvider(link.Provider)
			if providerConfig == nil {
				logger.Warnw("Provider config not found for admin enforcement", "provider", link.Provider)
				// SSO IS enabled and this provider is unknown - we should fail.
				return echo.NewHTTPError(http.StatusForbidden, "provider configuration not found")
			}

			if len(providerConfig.RequiredAdminGroups) == 0 {
				return next(c)
			}

			groupSet := make(map[string]struct{})
			for _, g := range sso.DeserializeStringArray(link.Groups) {
				normalized := strings.TrimSpace(strings.ToLower(g))
				if normalized != "" {
					groupSet[normalized] = struct{}{}
				}
			}

			for _, required := range providerConfig.RequiredAdminGroups {
				normalized := strings.TrimSpace(strings.ToLower(required))
				if _, ok := groupSet[normalized]; !ok {
					logger.Warnw("User missing required admin group",
						"userID", user.ID.String(),
						"requiredGroup", required,
						"provider", link.Provider,
					)
					return echo.NewHTTPError(http.StatusForbidden, "missing required admin groups")
				}
			}

			return next(c)
		}
	}
}
