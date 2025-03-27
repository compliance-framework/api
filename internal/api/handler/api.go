package handler

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func RegisterHandlers(server *api.Server, database *mongo.Database, logger *zap.SugaredLogger) {
	plansService := service.NewPlansService(database)

	findingService := service.NewFindingService(database)
	observationService := service.NewObservationService(database)
	componentService := service.NewComponentService(database)
	subjectService := service.NewSubjectService(database)
	heartbeatService := service.NewHeartbeatService(database)

	plansHandler := NewPlansHandler(logger, plansService)
	plansHandler.Register(server.API().Group("/assessment-plans"))

	findingHandler := NewFindingsHandler(logger, findingService, subjectService, componentService)
	findingHandler.Register(server.API().Group("/findings"))

	observationsHandler := NewObservationHandler(logger, observationService, subjectService, componentService)
	observationsHandler.Register(server.API().Group("/observations"))

	subjectsHandler := NewSubjectsHandler(logger, subjectService)
	subjectsHandler.Register(server.API().Group("/subjects"))

	heartbeatHandler := NewHeartbeatHandler(logger, heartbeatService)
	heartbeatHandler.Register(server.API().Group("/heartbeat"))
}
