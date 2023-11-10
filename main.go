package main

import (
	"context"
	"github.com/compliance-framework/configuration-service/runtime"
	"log"
	"os"

	"github.com/compliance-framework/configuration-service/event"
	"github.com/joho/godotenv"

	"github.com/compliance-framework/configuration-service/api"
	"github.com/compliance-framework/configuration-service/api/handler"
	"github.com/compliance-framework/configuration-service/event/bus"
	"github.com/compliance-framework/configuration-service/service"
	"github.com/compliance-framework/configuration-service/store/mongo"
	"go.uber.org/zap"
)

const (
	DefaultMongoURI = "mongodb://localhost:27017"
	DefaultNATSURI  = "nats://localhost:4222"
	DefaultPort     = ":8080"
)

type Config struct {
	MongoURI string
	NatsURI  string
}

//	@title			Compliance Framework Configuration Service API
//	@version		1.0
//	@description	This is the API for the Compliance Framework Configuration Service.

//	@host		localhost:8080
//	@BasePath	/api

// @externalDocs.description	OpenAPI
// @externalDocs.url			https://swagger.io/resources/open-api/
func main() {
	ctx := context.Background()

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := logger.Sugar()
	config := loadConfig()
	err = mongo.Connect(ctx, config.MongoURI, "cf")
	if err != nil {
		sugar.Fatalf("error connecting to mongo: %v", err)
	}

	err = bus.Listen(config.NatsURI, sugar)
	if err != nil {
		sugar.Fatalf("error connecting to nats: %v", err)
	}

	resultProcessor := runtime.NewProcessor(bus.Subscribe[event.ResultEvent])
	resultProcessor.Listen()

	server := api.NewServer(ctx, sugar)
	catalogStore := mongo.NewCatalogStore()
	catalogHandler := handler.NewCatalogHandler(catalogStore)
	catalogHandler.Register(server.API().Group("/catalog"))

	planService := service.NewPlanService(bus.Publish)
	planHandler := handler.NewPlanHandler(sugar, planService)
	planHandler.Register(server.API().Group("/plan"))

	metadataService := service.NewMetadataService()
	metadataHandler := handler.NewMetadataHandler(metadataService)
	metadataHandler.Register(server.API().Group("/metadata"))

	server.PrintRoutes()

	checkErr(server.Start(DefaultPort))
}

func loadConfig() (config Config) {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = DefaultMongoURI
	}

	natsURI := os.Getenv("NATS_URI")
	if natsURI == "" {
		natsURI = DefaultNATSURI
	}

	config = Config{
		MongoURI: mongoURI,
		NatsURI:  natsURI,
	}
	return config
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
