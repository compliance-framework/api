package handler

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/config"
	//"github.com/compliance-framework/configuration-service/internal/service"
	//"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func RegisterHandlers(server *api.Server, logger *zap.SugaredLogger, db *gorm.DB, config *config.Config) {
	dashboardHandler := NewDashboardHandler(logger, db)
	dashboardHandler.Register(server.API().Group("/dashboards"))

	heartbeatHandler := NewHeartbeatHandler(logger, db)
	heartbeatHandler.Register(server.API().Group("/agent/heartbeat"))

	evidenceHandler := NewEvidenceHandler(logger, db)
	evidenceHandler.Register(server.API().Group("/evidence"))
}
