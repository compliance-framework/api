package auth

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/oidc"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, cfg *config.Config, metrics *api.PrometheusMetrics) {
	authGroup := server.API().Group("/auth")

	authHandler := NewAuthHandler(logger, db, cfg, metrics)
	authHandler.Register(authGroup)

	oidcService, err := oidc.NewService(cfg.OIDC, logger)
	if err != nil {
		logger.Warnw("Failed to initialize OIDC service", "error", err)
	} else {
		oidcHandler := NewOIDCHandler(logger, db, cfg, oidcService, metrics)
		oidcHandler.Register(authGroup)
	}
}
