package auth

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, cfg *config.Config, metrics *api.PrometheusMetrics) {
	authGroup := server.API().Group("/auth")

	authHandler := NewAuthHandler(logger, db, cfg, metrics)
	authHandler.Register(authGroup)

	ssoService, err := sso.NewService(cfg.SSO, logger)
	if err != nil {
		logger.Warnw("Failed to initialize SSO service", "error", err)
	} else {
		ssoHandler := NewSSOHandler(logger, db, cfg, ssoService, metrics)
		ssoHandler.Register(authGroup)
	}
}
