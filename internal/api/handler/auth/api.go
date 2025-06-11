package auth

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/config"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config) {
	authGroup := server.API().Group("/auth")

	authHandler := NewAuthHandler(logger, db, config)
	authHandler.Register(authGroup)
}
