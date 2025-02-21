package handler

import (
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/service"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

func RegisterHandlers(server *api.Server, database *mongo.Database, logger *zap.SugaredLogger) {
	plansService := service.NewPlansService(database)
	resultService := service.NewResultsService(database)

	resultHandler := NewResultsHandler(logger, resultService, plansService)
	resultHandler.Register(server.API().Group("/assessment-results"))

	plansHandler := NewPlansHandler(logger, plansService)
	plansHandler.Register(server.API().Group("/assessment-plans"))
}
