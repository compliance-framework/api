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
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/scheduler"
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

func init() {
	RunCmd.Flags().String("digest-schedule", "@weekly", "Cron schedule for digest emails (e.g., '@hourly', '@daily', '@weekly', '0 9 * * 1' for Monday 9am)")
	RunCmd.Flags().Bool("digest-enabled", true, "Enable or disable the digest scheduler")
}

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

	// Initialize email service
	emailService, err := email.NewService(cfg.Email, sugar)
	if err != nil {
		sugar.Warnw("Failed to initialize email service, digests will be disabled", "error", err)
	}

	// Initialize digest service
	digestService := digest.NewService(db, emailService, cfg, sugar)

	// Initialize scheduler
	sched := scheduler.NewCronScheduler(sugar)

	// Register digest job
	digestEnabled, _ := cmd.Flags().GetBool("digest-enabled")
	digestSchedule, _ := cmd.Flags().GetString("digest-schedule")

	if digestEnabled {
		digestJob := digest.NewGlobalDigestJob(digestService, sugar)
		if err := sched.ScheduleCron(digestSchedule, digestJob); err != nil {
			sugar.Warnw("Failed to schedule digest job", "schedule", digestSchedule, "error", err)
		} else {
			sugar.Infow("Digest job scheduled", "schedule", digestSchedule)
		}
	} else {
		sugar.Infow("Digest scheduler disabled")
	}

	// Start the scheduler
	sched.Start()
	defer sched.Stop()

	metrics := api.NewMetricsHandler(ctx, sugar)
	server := api.NewServer(ctx, sugar, cfg, metrics)
	handler.RegisterHandlers(server, sugar, db, cfg, digestService, sched)
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
