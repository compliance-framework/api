package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/compliance-framework/configuration-service/internal/service"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/api/handler/oscal"

	logging "github.com/compliance-framework/configuration-service/internal/logging" // adjust as needed
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"

	"github.com/joho/godotenv"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

const (
	DefaultMongoURI = "mongodb://localhost:27017"
	DefaultPort     = ":8080"
	DefaultDBDriver = "postgres"
)

type Config struct {
	MongoURI           string
	AppPort            string
	DBDriver           string
	DBConnectionString string
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

	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	defer zapLogger.Sync() // flushes buffer, if any
	sugar := zapLogger.Sugar()

	config := loadConfig(sugar)

	mongoDatabase, err := connectMongo(ctx, options.Client().ApplyURI(config.MongoURI), "cf")
	if err != nil {
		sugar.Fatal(err)
	}
	defer mongoDatabase.Client().Disconnect(ctx)

	server := api.NewServer(ctx, sugar)

	handler.RegisterHandlers(server, mongoDatabase, sugar)

	var gormLogLevel gormLogger.LogLevel
	if os.Getenv("CCF_DB_DEBUG") == "1" {
		gormLogLevel = gormLogger.Info
	} else {
		gormLogLevel = gormLogger.Warn
	}

	//TODO: farm this out to specific function/file
	var db *gorm.DB
	switch config.DBDriver {
	case "postgres":
		db, err = gorm.Open(postgres.Open(config.DBConnectionString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   logging.NewZapGormLogger(sugar, gormLogLevel),
		})
	default:
		panic("unsupported DB driver: " + config.DBDriver)
	}
	if err != nil {
		sugar.Fatal("Failed to open database", "err", err)
	}

	err = service.MigrateUp(db)
	if err != nil {
		sugar.Fatal("Failed to migrate database", "err", err)
	}
	oscal.RegisterHandlers(server, sugar, db)

	server.PrintRoutes()

	checkErr(server.Start(config.AppPort), sugar)
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

func loadConfig(logger *zap.SugaredLogger) (config Config) {
	if err := godotenv.Load(".env"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Fatalf("Error loading .env file: %v", err)
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

	dbDriver := os.Getenv("CCF_DB_DRIVER")
	if dbDriver == "" {
		dbDriver = DefaultDBDriver
	}

	dbConnectionString, ok := os.LookupEnv("CCF_DB_CONNECTION")
	if !ok {
		switch dbDriver {
		case "postgres":
			dbConnectionString = "host=db user=postgres password=postgres dbname=ccf port=5432 sslmode=disable"
		default:
			logger.Fatalf("Unrecognised db driver: %s", dbDriver)
		}
	}

	logger.Infof("dbConnectionString: %s", dbConnectionString)

	config = Config{
		MongoURI:           mongoURI,
		AppPort:            port,
		DBDriver:           dbDriver,
		DBConnectionString: dbConnectionString,
	}

	return config
}

func checkErr(err error, logger *zap.SugaredLogger) {
	if err != nil {
		logger.Fatalf("An error occurred: %v", err)
	}
}
