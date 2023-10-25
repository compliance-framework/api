package main

import (
	"context"
	"log"
	"os"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/api/handler"
	"github.com/compliance-framework/configuration-service/event/bus"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/compliance-framework/configuration-service/store/mongo"
	"go.uber.org/zap"
)

func main() {
	ctx := context.Background()

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := logger.Sugar()

	mongoUri := getEnvironmentVariable("MONGO_URI", "mongodb://localhost:27017")
	err = mongo.Connect(ctx, mongoUri, "cf")
	if err != nil {
		sugar.Fatalf("error connecting to mongo: %v", err)
	}

	err = bus.Listen("nats://localhost:4222", sugar)
	if err != nil {
		sugar.Fatalf("error connecting to nats: %v", err)
	}

	server := api.NewServer(ctx)
	catalogStore := mongo.NewCatalogStore()
	controlHandler := handler.NewCatalogHandler(catalogStore)
	controlHandler.Register(server.API())

	planService := service.NewPlanService(bus.Publish)
	resultService := service.NewResultService()
	planHandler := handler.NewPlanHandler(sugar, planService, resultService)
	planHandler.Register(server.API())

	metadataService := service.NewMetadataService()
	metadataHandler := handler.NewMetadataHandler(metadataService)
	metadataHandler.Register(server.API())

	checkErr(server.Start(":8080"))
}

func getEnvironmentVariable(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
