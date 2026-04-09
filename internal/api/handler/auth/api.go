package auth

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/compliance-framework/api/internal/service/worker"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, cfg *config.Config, metrics *api.PrometheusMetrics, emailService *email.Service, workerService *worker.Service) {
	authGroup := server.API().Group("/auth")

	// Use provided email service or create a new one
	var err error
	if emailService == nil {
		emailService, err = email.NewService(cfg.Email, logger)
		if err != nil {
			logger.Warnw("Failed to initialize email service", "error", err)
			emailService = nil // Set to nil so handlers can check if it's available
		}
	}

	authHandler := NewAuthHandler(logger, db, cfg, metrics, emailService, workerService)
	authHandler.Register(authGroup)

	slackLinkHandler := NewSlackLinkHandler(logger, db, cfg)
	slackLinkHandler.Register(authGroup, middleware.JWTMiddleware(cfg.JWTPublicKey))

	ssoService, err := sso.NewService(cfg.SSO, logger)
	if err != nil {
		logger.Warnw("Failed to initialize SSO service", "error", err)
	} else {
		ssoHandler := NewSSOHandler(logger, db, cfg, ssoService, metrics)
		ssoHandler.Register(authGroup)
	}
}
