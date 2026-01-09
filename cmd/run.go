package cmd

import (
	"context"
	"log"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/handler/auth"
	"github.com/compliance-framework/api/internal/api/handler/oscal"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	RunCmd = &cobra.Command{
		Use:   "run",
		Short: "Run the compliance framework API",
		Run:   RunServer,
	}
)

func RunServer(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	var sugar *zap.SugaredLogger
	if viper.GetBool("use_dev_logger") {
		sugar = zap.Must(zap.NewDevelopment()).Sugar()
	} else {
		sugar = zap.Must(zap.NewProduction()).Sugar()
	}

	defer func() {
		if err := sugar.Sync(); err != nil {
			log.Printf("failed to sync zap logger: %v", err)
		}
	}()

	cfg := config.NewConfig(sugar)

	db, err := service.ConnectSQLDb(ctx, cfg, sugar)
	if err != nil {
		sugar.Fatalw("Failed to connect to SQL database", "error", err)
	}

	err = service.MigrateUp(db)
	if err != nil {
		sugar.Fatalw("Failed to migrate database", "error", err)
	}

	metrics := api.NewMetricsHandler(ctx, sugar)
	server := api.NewServer(ctx, sugar, cfg, metrics)
	handler.RegisterHandlers(server, sugar, db, cfg)
	oscal.RegisterHandlers(server, sugar, db, cfg)
	auth.RegisterHandlers(server, sugar, db, cfg, metrics)

	sugar.Infow("Allowed Origins", "origins", cfg.APIAllowedOrigins)
	server.PrintRoutes()

	if cfg.MetricsEnabled {
		sugar.Infow("Starting metrics server", "port", cfg.MetricsPort)
		metrics.StartMetricsServer(cfg.MetricsPort)
	}

	if err := server.Start(cfg.AppPort); err != nil {
		sugar.Fatalw("Failed to start server", "error", err)
	}
}
