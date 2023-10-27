package main

import (
	"context"
	"github.com/joho/godotenv"
	"log"
	"os"

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
	NATSURI  string
}

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

	err = bus.Listen(config.NATSURI, sugar)
	if err != nil {
		sugar.Fatalf("error connecting to nats: %v", err)
	}

	server := api.NewServer(ctx)
	catalogStore := mongo.NewCatalogStore()
	controlHandler := handler.NewCatalogHandler(catalogStore)
	controlHandler.Register(server.API())

	planService := service.NewPlanService(bus.Publish)
	planHandler := handler.NewPlanHandler(sugar, planService)
	planHandler.Register(server.API())

	metadataService := service.NewMetadataService()
	metadataHandler := handler.NewMetadataHandler(metadataService)
	metadataHandler.Register(server.API())

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
		NATSURI:  natsURI,
	}
	return config
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
