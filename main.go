package main

import (
	"context"
	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/api/handler"
	"github.com/compliance-framework/configuration-service/store/mongo"
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
	err = mongo.Connect(ctx, mongoUri, "cf")
	if err != nil {
		sugar.Fatalf("error connecting to mongo: %v", err)
	}

	server := api.NewServer(ctx)
	catalogStore := mongo.NewCatalogStore()
	controlHandler := handler.NewCatalogHandler(catalogStore)
	controlHandler.Register(server.API())
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
