package cmd

import (
	"context"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"log"
)

func newMigrateCMD() *cobra.Command {
	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Manage database migrations",
	}

	migrate.AddCommand(&cobra.Command{
		Use:   "up",
		Short: "Upgrade database schema",
		Long:  "This command will ensure the database schema matches what has been defined in the CCF API. It will upgrade any existing entities to match the CCF data structures",
		Run:   migrateUp,
	})

	migrate.AddCommand(&cobra.Command{
		Use:   "down",
		Short: "Remove the database schema",
		Long:  "Completely remove the database schema created by CCF",
		Run:   migrateDown,
	})

	migrate.AddCommand(&cobra.Command{
		Use:   "refresh",
		Short: "Refresh the database schema",
		Long:  "Completely remove and recreate the database schema for CCF",
		Run: func(cmd *cobra.Command, args []string) {
			migrateDown(cmd, args)
			migrateUp(cmd, args)
		},
	})

	return migrate
}

func migrateUp(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync() // flushes buffer, if any

	cfg := config.NewConfig(sugar)
	ctx := context.Background()
	db, err := service.ConnectSQLDb(ctx, cfg, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	err = service.MigrateUp(db)
	if err != nil {
		panic(err)
	}
}

func migrateDown(cmd *cobra.Command, args []string) {
	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := zapLogger.Sugar()
	defer zapLogger.Sync() // flushes buffer, if any

	cfg := config.NewConfig(sugar)
	ctx := context.Background()
	db, err := service.ConnectSQLDb(ctx, cfg, sugar)
	if err != nil {
		panic("failed to connect database")
	}

	err = service.MigrateDown(db)
	if err != nil {
		panic(err)
	}
}
