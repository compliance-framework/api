package handler

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func RegisterHandlers(server *api.Server, database *mongo.Database, logger *zap.SugaredLogger) {
	dashboardService := service.NewDashboardService(database)
	findingService := service.NewFindingService(database)
	observationService := service.NewObservationService(database)
	componentService := service.NewComponentService(database)
	subjectService := service.NewSubjectService(database)
	heartbeatService := service.NewHeartbeatService(database)
	catalogService := service.NewCatalogService(database)
	controlService := service.NewCatalogControlService(database)
	groupService := service.NewCatalogGroupService(database)

	dashboardHandler := NewDashboardHandler(logger, dashboardService)
	dashboardHandler.Register(server.API().Group("/dashboards"))

	findingHandler := NewFindingsHandler(logger, findingService, subjectService, componentService)
	findingHandler.Register(server.API().Group("/findings"))

	observationsHandler := NewObservationHandler(logger, observationService, subjectService, componentService)
	observationsHandler.Register(server.API().Group("/observations"))

	subjectsHandler := NewSubjectsHandler(logger, subjectService)
	subjectsHandler.Register(server.API().Group("/subjects"))

	heartbeatHandler := NewHeartbeatHandler(logger, heartbeatService)
	heartbeatHandler.Register(server.API().Group("/heartbeat"))

	catalogHandler := NewCatalogHandler(logger, catalogService, groupService, controlService)
	catalogHandler.Register(server.API().Group("/catalogs"))

	groupsHandler := NewCatalogGroupHandler(logger, groupService)
	groupsHandler.Register(server.API().Group("/groups"))

	controlsHandler := NewCatalogControlHandler(logger, controlService)
	controlsHandler.Register(server.API().Group("/controls"))
}
