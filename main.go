package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/api/handler/oscal"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

	db, err := gorm.Open(sqlite.Open("data/ccf.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	err = migrateDB(db)
	if err != nil {
		sugar.Fatal("Failed to migrate database", "err", err)
	}

	oscal.RegisterHandlers(server, sugar, db)

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

func migrateDB(db *gorm.DB) error {
	err := db.AutoMigrate(
		&relational.Location{},
		&relational.Party{},
		&relational.BackMatterResource{},
		&relational.BackMatter{},
		&relational.Role{},
		&relational.Revision{},
		&relational.Control{},
		&relational.Group{},
		&relational.ResponsibleParty{},
		&relational.Action{},
		&relational.Metadata{},
		&relational.Catalog{},
		&relational.ControlStatementImplementation{},
		&relational.ImplementedRequirementControlImplementation{},
		&relational.ControlImplementationSet{},
		&relational.ComponentDefinition{},
		&relational.Capability{},
		&relational.DefinedComponent{},
		&relational.Diagram{},
		&relational.DataFlow{},
		&relational.NetworkArchitecture{},
		&relational.AuthorizationBoundary{},
		&relational.InformationType{},
		&relational.SystemInformation{},
		&relational.SystemCharacteristics{},
		&relational.AuthorizedPrivilege{},
		&relational.SystemUser{},
		&relational.LeveragedAuthorization{},
		&relational.SystemComponent{},
		&relational.ImplementedComponent{},
		&relational.InventoryItem{},
		&relational.SystemImplementation{},
		&relational.ControlImplementationResponsibility{},
		&relational.ProvidedControlImplementation{},
		&relational.SatisfiedControlImplementationResponsibility{},
		&relational.Export{},
		&relational.InheritedControlImplementation{},
		&relational.ByComponent{},
		&relational.Statement{},
		&relational.ImplementedRequirement{},
		&relational.ControlImplementation{},
		&relational.SystemSecurityPlan{},
	)
	return err
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
