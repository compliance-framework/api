package handler

import (
	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/middleware"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/scheduler"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config, digestService *digest.Service, sched scheduler.Scheduler) {
	healthHandler := NewHealthHandler(logger, db)
	healthHandler.Register(server.API().Group("/health"))

	filterHandler := NewFilterHandler(logger, db)
	filterHandler.Register(server.API().Group("/filters"))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	heartbeatHandler.Register(server.API().Group("/agent/heartbeat"))

	evidenceHandler := NewEvidenceHandler(logger, db, config)
	evidenceHandler.Register(server.API().Group("/evidence"))

	userHandler := NewUserHandler(logger, db)

	adminGroup := server.API().Group("/admin/users")
	adminGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	adminGroup.Use(middleware.RequireAdminGroups(db, config, logger))
	userHandler.Register(adminGroup)

	userGroup := server.API().Group("/users")
	userGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
	userHandler.RegisterSelfRoutes(userGroup)

	// Digest handler (admin only)
	if digestService != nil && sched != nil {
		digestHandler := NewDigestHandler(digestService, sched, logger)
		digestGroup := server.API().Group("/admin/digest")
		digestGroup.Use(middleware.JWTMiddleware(config.JWTPublicKey))
		digestGroup.Use(middleware.RequireAdminGroups(db, config, logger))
		digestHandler.Register(digestGroup)
	}
}
