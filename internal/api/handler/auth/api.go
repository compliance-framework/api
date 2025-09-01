package auth

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, metrics *api.PrometheusMetrics) {
	authGroup := server.API().Group("/auth")

	authHandler := NewAuthHandler(logger, db, config, metrics)
	authHandler.Register(authGroup)
}
