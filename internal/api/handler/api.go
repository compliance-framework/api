package handler

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config) {
	filterHandler := NewFilterHandler(logger, db)
	filterHandler.Register(server.API().Group("/filters"))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	heartbeatHandler.Register(server.API().Group("/agent/heartbeat"))

	evidenceHandler := NewEvidenceHandler(logger, db)
	evidenceHandler.Register(server.API().Group("/evidence"))

	userGroup := server.API().Group("/users")
	userGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler := NewUserHandler(logger, db)
	userHandler.Register(userGroup)

}
