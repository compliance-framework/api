package cmd

import (
	"context"
	"log"

	"github.com/compliance-framework/configuration-service/internal/api"
	"github.com/compliance-framework/configuration-service/internal/api/handler"
	"github.com/compliance-framework/configuration-service/internal/api/handler/auth"
	"github.com/compliance-framework/configuration-service/internal/api/handler/oscal"
	"github.com/compliance-framework/configuration-service/internal/config"
	"github.com/compliance-framework/configuration-service/internal/service"
	"github.com/spf13/cobra"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
)

var (
	RunCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the configuration service API",
		Run:   RunServer,
	}
)

func RunServer(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	defer zapLogger.Sync() // flushes buffer, if any
	sugar := zapLogger.Sugar()

	config := config.NewConfig(sugar)

	mongoDatabase, err := service.ConnectMongo(ctx, options.Client().ApplyURI(config.MongoURI), "cf")
	if err != nil {
		sugar.Fatal(err)
	}
	defer mongoDatabase.Client().Disconnect(ctx)

	db, err := service.ConnectSQLDb(config, sugar)
	if err != nil {
		sugar.Fatal("Failed to connect to SQL database", "err", err)
	}

	err = service.MigrateUp(db)
	if err != nil {
		sugar.Fatal("Failed to migrate database", "err", err)
	}

	server := api.NewServer(ctx, sugar, config)

	handler.RegisterHandlers(server, mongoDatabase, sugar)
	oscal.RegisterHandlers(server, sugar, db, config)
	auth.RegisterHandlers(server, sugar, db, config)

	sugar.Infow("Allowed Origins", "origins", config.APIAllowedOrigins)
	server.PrintRoutes()

	checkErr(server.Start(config.AppPort), sugar)
}

func checkErr(err error, logger *zap.SugaredLogger) {
	if err != nil {
		logger.Fatalf("An error occurred: %v", err)
	}
}
