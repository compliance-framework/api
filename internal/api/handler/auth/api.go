package auth

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/sso"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, cfg *config.Config, metrics *api.PrometheusMetrics) {
	authGroup := server.API().Group("/auth")

	// Initialize email service
	emailService, err := email.NewService(cfg.Email, logger)
	if err != nil {
		logger.Warnw("Failed to initialize email service", "error", err)
		emailService = nil // Set to nil so handlers can check if it's available
	}

	authHandler := NewAuthHandler(logger, db, cfg, metrics, emailService)
	authHandler.Register(authGroup)

	ssoService, err := sso.NewService(cfg.SSO, logger)
	if err != nil {
		logger.Warnw("Failed to initialize SSO service", "error", err)
	} else {
		ssoHandler := NewSSOHandler(logger, db, cfg, ssoService, metrics)
		ssoHandler.Register(authGroup)
	}
}
