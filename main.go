package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/api/handler/oscal"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

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

	//TODO: farm this out to specific function/file
	var db *gorm.DB
	switch config.DBDriver {
	case "postgres":
		db, err = gorm.Open(postgres.Open(config.DBConnectionString), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
		})
	default:
		panic("unsupported DB driver: " + config.DBDriver)
	}
	if err != nil {
		sugar.Fatal("Failed to open database", "err", err)
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
		&relational.SelectControlById{},
		&relational.Import{},
		&relational.Merge{},
		&relational.ParameterSetting{},
		&relational.Addition{},
		&relational.Alteration{},
		&relational.Modify{},
		&relational.Profile{},
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
			log.Fatalf("Unrecognised db driver: %s", dbDriver)
		}
	}

	log.Printf("dbConnectionString: %s", dbConnectionString)

	config = Config{
		MongoURI:           mongoURI,
		AppPort:            port,
		DBDriver:           dbDriver,
		DBConnectionString: dbConnectionString,
	}

	return config
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
