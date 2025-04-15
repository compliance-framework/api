package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"

	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

const (
	DefaultMongoURI = "mongodb://localhost:27017"
	DefaultPort     = ":8080"
)

type Config struct {
	MongoURI string
	AppPort  string
}

// @title						Continuous Compliance Framework API
// @version					1
// @description				This is the API for the Continuous Compliance Framework.
// @host						localhost:8080
// @accept						json
// @produce					json
// @BasePath					/api
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

	mongoDatabase, err := connectMongo(ctx, options.Client().ApplyURI(config.MongoURI), "cf")
	if err != nil {
		sugar.Fatal(err)
	}
	defer mongoDatabase.Client().Disconnect(ctx)

	server := api.NewServer(ctx, sugar)

	handler.RegisterHandlers(server, mongoDatabase, sugar)

	server.PrintRoutes()

	checkErr(server.Start(config.AppPort))
}

func connectMongo(ctx context.Context, clientOptions *options.ClientOptions, databaseName string) (*mongo.Database, error) {
	client, err := mongo.Connect(ctx, clientOptions)

	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}

	return client.Database(databaseName), nil
}

func loadConfig() (config Config) {
	if err := godotenv.Load(".env"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = DefaultMongoURI
	}

	port := DefaultPort
	appPort, portSet := os.LookupEnv("APP_PORT")
	if portSet {
		port = fmt.Sprintf(":%s", appPort)
	}

	config = Config{
		MongoURI: mongoURI,
		AppPort:  port,
	}
	return config
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
