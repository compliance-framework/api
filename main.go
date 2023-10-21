package main

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/adapter/api"
	"github.com/compliance-framework/configuration-service/internal/adapter/api/handler"
	"github.com/compliance-framework/configuration-service/internal/adapter/store/mongo"
	"github.com/compliance-framework/configuration-service/internal/domain/service"
	"go.uber.org/zap"
	"log"
	"os"
)

func main() {
	ctx := context.Background()

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := logger.Sugar()

	mongoUri := getEnvironmentVariable("MONGO_URI", "mongodb://mongo:27017")
	store := mongo.NewStore(ctx, mongoUri, "cf")
	err = store.Connect()
	if err != nil {
		sugar.Fatalf("error connecting to mongo: %v", err)
	}

	server := api.NewServer(ctx)
	controlService := service.NewControlService()
	controlHandler := handler.NewControlHandler(controlService)
	server.Route("GET", "/controls/:id", controlHandler.GetControl)
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
