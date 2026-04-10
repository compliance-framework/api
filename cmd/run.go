package cmd

import (
	"context"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/api/handler/auth"
	"github.com/compliance-framework/api/internal/api/handler/oscal"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service"
	"github.com/compliance-framework/api/internal/service/digest"
	"github.com/compliance-framework/api/internal/service/email"
	evidencesvc "github.com/compliance-framework/api/internal/service/relational/evidence"
	templatesvc "github.com/compliance-framework/api/internal/service/relational/templates"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/compliance-framework/api/internal/service/worker"
	"github.com/compliance-framework/api/internal/workflow"
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

	bootstrapAction, privateKeyPath, publicKeyPath, bootstrapConfigured, err := bootstrapConfiguredJWTKeys(defaultJWTKeyBitSize, false)
	if err != nil {
		sugar.Fatalw(
			"Failed to bootstrap JWT key files",
			"error",
			err,
			"private_key_path",
			privateKeyPath,
			"public_key_path",
			publicKeyPath,
		)
	}
	if bootstrapConfigured {
		sugar.Infow(
			"JWT key bootstrap completed",
			"action",
			bootstrapAction,
			"private_key_path",
			privateKeyPath,
			"public_key_path",
			publicKeyPath,
		)
	}

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

	slackService, err := slacksvc.NewService(cfg.Slack, sugar)
	if err != nil {
		sugar.Warnw("Failed to initialize slack service, Slack digests will be disabled", "error", err)
	}

	// Initialize digest service (without worker service initially)
	digestService := digest.NewService(db, emailService, slackService, nil, cfg, sugar)

	// profileResolver bridges the worker package and the oscal handler package without creating
	// a circular import. It uses the pivot table fast path first, then falls back to full
	// recursive profile resolution via oscal.FindFullProfile / oscal.GetControlIDsMapFromProfile.
	profileResolver := &oscalProfileControlResolver{db: db}

	// Initialize worker service with digest support
	workerService, err := worker.NewServiceWithDigest(cfg.Worker, db, emailService, digestService, cfg, profileResolver, sugar)
	if err != nil {
		sugar.Fatalw("Failed to initialize worker service", "error", err)
	}

	// Set worker service reference in digest service to avoid circular dependency
	digestService.SetWorkerService(workerService)

	// Run River migrations
	if err := workerService.Migrate(ctx); err != nil {
		sugar.Fatalw("Failed to run River migrations", "error", err)
	}

	// Start worker service
	if err := workerService.Start(ctx); err != nil {
		sugar.Fatalw("Failed to start worker service", "error", err)
	}

	// Initialize workflow manager
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	workflowInstService := workflows.NewWorkflowInstanceService(db)
	stepExecService := workflows.NewStepExecutionService(db, nil)
	workflowManager := workflow.NewManager(
		workerService.GetClient(),
		workflowExecService,
		workflowInstService,
		stepExecService,
		sugar,
		workerService,
	)

	metrics := api.NewMetricsHandler(ctx, sugar)
	server := api.NewServer(ctx, sugar, cfg, metrics)

	// Create subject template service for component definition resolution
	subjectTemplateService := templatesvc.NewSubjectTemplateService(db)

	// Create evidence service with worker service for risk job enqueuing
	evidenceService := evidencesvc.NewEvidenceService(db, sugar, cfg, workerService,
		evidencesvc.WithComponentDefinitionResolver(subjectTemplateService))

	// Create services struct for API handlers
	services := &handler.APIServices{
		EvidenceService:      evidenceService,
		RiskEnqueuer:         workerService,
		DigestService:        digestService,
		WorkflowManager:      workflowManager,
		NotificationEnqueuer: workerService,
		DAGExecutor:          workerService.GetDAGExecutor(),
	}

	handler.RegisterHandlers(server, sugar, db, cfg, services)
	oscal.RegisterHandlers(server, sugar, db, cfg, evidenceService, workerService)
	auth.RegisterHandlers(server, sugar, db, cfg, metrics, emailService, workerService)

	sugar.Infow("Allowed Origins", "origins", cfg.APIAllowedOrigins)
	server.PrintRoutes()

	if cfg.MetricsEnabled {
		sugar.Infow("Starting metrics server", "port", cfg.MetricsPort)
		metrics.StartMetricsServer(cfg.MetricsPort)
	}

	if cfg.PprofEnabled {
		sugar.Infow("Starting pprof server", "port", cfg.PprofPort)
		go func() {
			if err := http.ListenAndServe(cfg.PprofPort, nil); err != nil {
				sugar.Errorw("Failed to start pprof server", "error", err)
			}
		}()
	}

	if err := server.Start(cfg.AppPort); err != nil {
		sugar.Fatalw("Failed to start server", "error", err)
	}

	defer func() {
		if err := workerService.Stop(ctx); err != nil {
			sugar.Errorw("Failed to stop worker service", "error", err)
		}
	}()
}
