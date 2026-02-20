package worker

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Service manages the River client and workers
type Service struct {
	client    *river.Client[pgx.Tx]
	config    *config.WorkerConfig
	db        *gorm.DB
	emailSvc  *email.Service
	digestSvc DigestService
	userRepo  UserRepository
	logger    *zap.SugaredLogger
	started   bool
	startedMu sync.RWMutex
	pgxPool   *pgxpool.Pool
	digestCfg *config.Config

	// Workflow services
	workflowExecutor *workflow.DAGExecutor
}

type riverClientProxy struct {
	client *river.Client[pgx.Tx]
}

func (p *riverClientProxy) InsertMany(ctx context.Context, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error) {
	if p.client == nil {
		return nil, fmt.Errorf("river client not initialized")
	}
	return p.client.InsertMany(ctx, params)
}

type notificationEnqueuerProxy struct {
	enqueuer workflow.NotificationEnqueuer
}

func (p *notificationEnqueuerProxy) EnqueueWorkflowTaskAssigned(ctx context.Context, stepExecution *workflows.StepExecution) error {
	if p.enqueuer == nil {
		return fmt.Errorf("notification enqueuer not initialized")
	}
	return p.enqueuer.EnqueueWorkflowTaskAssigned(ctx, stepExecution)
}

func (p *notificationEnqueuerProxy) EnqueueWorkflowExecutionFailed(ctx context.Context, execution *workflows.WorkflowExecution) error {
	if p.enqueuer == nil {
		return fmt.Errorf("notification enqueuer not initialized")
	}
	return p.enqueuer.EnqueueWorkflowExecutionFailed(ctx, execution)
}

// NewServiceWithDigest creates a new worker service with digest support
func NewServiceWithDigest(
	cfg *config.WorkerConfig,
	db *gorm.DB,
	emailSvc *email.Service,
	digestSvc DigestService,
	digestCfg *config.Config,
	logger *zap.SugaredLogger,
) (*Service, error) {
	if !cfg.Enabled {
		logger.Info("Worker service is disabled")
		return &Service{
			config:    cfg,
			db:        db,
			emailSvc:  emailSvc,
			digestSvc: digestSvc,
			digestCfg: digestCfg,
			logger:    logger,
			started:   false,
		}, nil
	}

	if emailSvc == nil {
		return nil, fmt.Errorf("email service is required for worker service")
	}

	// Get pgx pool from GORM
	// Note: Creating a separate pgx pool for River workers is acceptable here because:
	// 1. River requires a pgxpool.Pool specifically, not GORM's generic interface
	// 2. We use conservative pool settings to avoid exhaustion
	// 3. The pools share the same database but operate independently
	var pgxPool *pgxpool.Pool
	// Since GORM's ConnPool doesn't directly expose pgxpool.Pool,
	// we need to create a new pool from the DSN
	dialector, ok := db.Dialector.(*postgres.Dialector)
	if !ok {
		return nil, fmt.Errorf("worker service requires a postgres dialector, got %T", db.Dialector)
	}
	dsn := dialector.DSN

	// Configure pgx pool with conservative settings to avoid connection exhaustion
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pgx pool config: %w", err)
	}
	// Limit connections to avoid exhausting database connections
	// Use a small fraction of typical connection limits
	poolConfig.MaxConns = 10 // Conservative limit for worker pool
	poolConfig.MinConns = 2  // Keep minimum connections warm

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgx pool: %w", err)
	}
	pgxPool = pool

	// Create workflow services
	stepExecService := workflows.NewStepExecutionService(db, nil)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)
	workflowInstService := workflows.NewWorkflowInstanceService(db)
	roleAssignmentService := workflows.NewRoleAssignmentService(db)

	// Create proxies to handle circular dependency (Service implements NotificationEnqueuer but is built after workflow objects)
	clientProxy := &riverClientProxy{}
	enqueuerProxy := &notificationEnqueuerProxy{}

	// Create assignment service
	assignmentService := workflow.NewAssignmentService(roleAssignmentService, stepExecService, db, logger, enqueuerProxy)

	// Create workflow executor
	workflowLogger := log.New(os.Stdout, "[WORKFLOW] ", log.LstdFlags)
	executor := workflow.NewDAGExecutor(
		stepExecService,
		workflowExecService,
		stepDefService,
		assignmentService,
		workflowLogger,
		enqueuerProxy,
	)

	// Initialize evidence integration and set it on the executor
	evidenceIntegration := workflow.NewEvidenceIntegration(db, logger)
	executor.SetEvidenceIntegration(evidenceIntegration)

	// Set evidence integration on step execution service
	stepExecService.SetEvidenceCreator(evidenceIntegration)

	// Set evidence integration on workflow execution service
	workflowExecService.SetEvidenceCreator(evidenceIntegration)

	// Create workflow workers
	workflowExecutionWorker := workflow.NewWorkflowExecutionWorker(executor, evidenceIntegration, logger)

	// Create Manager with proxy
	workflowManager := workflow.NewManager(
		clientProxy,
		workflowExecService,
		workflowInstService,
		stepExecService,
		logger,
		enqueuerProxy,
	)

	// Determine grace period days for the workflow scheduler, with safe defaults.
	gracePeriodDays := config.DefaultWorkflowConfig().GracePeriodDays
	overdueCheckEnabled := config.DefaultWorkflowConfig().OverdueCheckEnabled
	if digestCfg != nil && digestCfg.Workflow != nil {
		gracePeriodDays = digestCfg.Workflow.GracePeriodDays
		overdueCheckEnabled = digestCfg.Workflow.OverdueCheckEnabled
	}

	overdueService := workflow.NewOverdueService(
		db,
		workflowExecService,
		stepExecService,
		evidenceIntegration,
		logger,
		gracePeriodDays,
		enqueuerProxy,
	)

	schedulerWorker := workflow.NewWorkflowSchedulerWorker(
		workflowManager,
		workflowInstService,
		overdueService,
		overdueCheckEnabled,
		logger,
		gracePeriodDays,
	)

	// Register workers with dependencies injected
	// We start with the email/digest workers
	userRepo := NewGORMUserRepository(db)
	webBaseURL := ""
	if digestCfg != nil {
		webBaseURL = digestCfg.WebBaseURL
	}
	workers := Workers(emailSvc, digestSvc, userRepo, db, webBaseURL, logger)

	// Add workflow workers
	river.AddWorker(workers, river.WorkFunc(workflowExecutionWorker.Work))
	river.AddWorker(workers, river.WorkFunc(schedulerWorker.Work))

	// Add due-soon checker worker (uses clientProxy which is wired to the real client after construction)
	dueSoonCheckerWorker := NewDueSoonCheckerWorker(db, clientProxy, logger)
	river.AddWorker(workers, river.WorkFunc(dueSoonCheckerWorker.Work))

	// Add workflow task digest checker worker
	digestCheckerWorker := NewWorkflowTaskDigestCheckerWorker(db, clientProxy, logger)
	river.AddWorker(workers, river.WorkFunc(digestCheckerWorker.Work))

	// Configure periodic jobs
	periodicJobs := periodicJobsFromConfig(digestCfg, logger)

	// Create River client with pgxv5 driver
	riverConfig := buildRiverConfig(cfg, workers, periodicJobs)

	// Create the client
	client, err := river.NewClient(riverpgxv5.New(pgxPool), &riverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create River client: %w", err)
	}

	// Update proxy with actual client
	clientProxy.client = client

	service := &Service{
		client:    client,
		config:    cfg,
		db:        db,
		emailSvc:  emailSvc,
		digestSvc: digestSvc,
		userRepo:  userRepo,
		digestCfg: digestCfg,
		logger:    logger,
		started:   false,
		pgxPool:   pgxPool,

		workflowExecutor: executor,
	}

	// Wire the service itself into the notification enqueuer proxy now that it is fully constructed.
	enqueuerProxy.enqueuer = service

	return service, nil
}

// GetDAGExecutor returns the shared DAG executor used by workflow River workers.
// Returns nil when the worker service is disabled.
func (s *Service) GetDAGExecutor() *workflow.DAGExecutor {
	return s.workflowExecutor
}

// Start starts the worker service
func (s *Service) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("Worker service is disabled, not starting")
		return nil
	}

	s.startedMu.Lock()
	defer s.startedMu.Unlock()

	if s.started {
		s.logger.Warn("Worker service is already started")
		return nil
	}

	s.logger.Infow("Starting worker service",
		"workers", s.config.Workers,
		"queue", s.config.Queue,
	)

	// Start the workers with the provided context (no dependency injection needed)
	if err := s.client.Start(ctx); err != nil {
		return fmt.Errorf("failed to start River client: %w", err)
	}

	s.started = true
	s.logger.Info("Worker service started successfully")
	return nil
}

// Stop stops the worker service
func (s *Service) Stop(ctx context.Context) error {
	s.startedMu.Lock()
	defer s.startedMu.Unlock()

	if !s.config.Enabled || !s.started {
		s.logger.Info("Worker service is not running")
		return nil
	}

	s.logger.Info("Stopping worker service")

	// Stop the client with a graceful shutdown period
	stopCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := s.client.Stop(stopCtx); err != nil {
		s.logger.Errorw("Failed to stop River client gracefully", "error", err)
		return fmt.Errorf("failed to stop River client: %w", err)
	}

	// Close pgx pool
	if s.pgxPool != nil {
		s.pgxPool.Close()
	}

	s.started = false
	s.logger.Info("Worker service stopped")
	return nil
}

// IsStarted returns true if the worker service is started
func (s *Service) IsStarted() bool {
	s.startedMu.RLock()
	defer s.startedMu.RUnlock()
	return s.started
}

// GetClient returns the River client for job insertion
func (s *Service) GetClient() *river.Client[pgx.Tx] {
	return s.client
}

// Migrate runs River migrations
func (s *Service) Migrate(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("Worker service is disabled, skipping migration")
		return nil
	}

	if s.pgxPool == nil {
		return fmt.Errorf("pgx pool is not initialized - worker service may be disabled")
	}

	// Get migrator from the driver
	migrator, err := rivermigrate.New(riverpgxv5.New(s.pgxPool), &rivermigrate.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}

	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{})
	if err != nil {
		return fmt.Errorf("failed to run River migrations: %w", err)
	}

	s.logger.Info("River migrations completed successfully")
	return nil
}

// NewDigestPeriodicJob creates a periodic job for digest scheduling
func NewDigestPeriodicJob(cronSchedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	schedule := parseCronScheduleWithFallback(cronSchedule, "@weekly", "digest", logger)

	return river.NewPeriodicJob(
		schedule,
		func() (river.JobArgs, *river.InsertOpts) {
			return &SendGlobalDigestArgs{}, &river.InsertOpts{
				Queue:       "digest",
				MaxAttempts: 3,
			}
		},
		&river.PeriodicJobOpts{
			RunOnStart: false, // Don't run immediately on startup
		},
	)
}

func NewWorkflowSchedulerPeriodicJob(cronSchedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	schedule := parseCronScheduleWithFallback(cronSchedule, "@every 15m", "workflow scheduler", logger)

	return river.NewPeriodicJob(
		schedule,
		workflowSchedulerPeriodicJobConstructor,
		&river.PeriodicJobOpts{
			RunOnStart: false,
		},
	)
}

func workflowSchedulerPeriodicJobConstructor() (river.JobArgs, *river.InsertOpts) {
	return &workflow.ScheduleWorkflowsArgs{}, workflow.JobInsertOptionsForScheduler()
}

func parseCronScheduleWithFallback(cronSchedule string, fallback string, jobName string, logger *zap.SugaredLogger) cron.Schedule {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	schedule, err := parser.Parse(cronSchedule)
	if err != nil {
		logger.Errorw("Failed to parse cron schedule, using fallback", "job", jobName, "schedule", cronSchedule, "fallback", fallback, "error", err)
		schedule, _ = parser.Parse(fallback)
	}
	return schedule
}

func NewDueSoonCheckerPeriodicJob(schedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	sched := parseCronScheduleWithFallback(schedule, "0 8 * * *", "due-soon checker", logger)

	return river.NewPeriodicJob(
		sched,
		func() (river.JobArgs, *river.InsertOpts) {
			return &DueSoonCheckerArgs{}, &river.InsertOpts{
				Queue:       "email",
				MaxAttempts: 3,
			}
		},
		&river.PeriodicJobOpts{
			RunOnStart: false,
		},
	)
}

func NewWorkflowTaskDigestPeriodicJob(schedule string, logger *zap.SugaredLogger) *river.PeriodicJob {
	sched := parseCronScheduleWithFallback(schedule, "0 8 * * *", "workflow task digest", logger)

	return river.NewPeriodicJob(
		sched,
		func() (river.JobArgs, *river.InsertOpts) {
			return &WorkflowTaskDigestCheckerArgs{}, &river.InsertOpts{
				Queue:       "digest",
				MaxAttempts: 3,
			}
		},
		&river.PeriodicJobOpts{
			RunOnStart: false,
		},
	)
}

func periodicJobsFromConfig(cfg *config.Config, logger *zap.SugaredLogger) []*river.PeriodicJob {
	var periodicJobs []*river.PeriodicJob
	if cfg == nil {
		return periodicJobs
	}
	if cfg.DigestEnabled {
		periodicJobs = append(periodicJobs, NewDigestPeriodicJob(cfg.DigestSchedule, logger))
	}
	if cfg.Workflow != nil && cfg.Workflow.SchedulerEnabled {
		periodicJobs = append(periodicJobs, NewWorkflowSchedulerPeriodicJob(cfg.Workflow.Schedule, logger))
	}
	if cfg.Workflow != nil && cfg.Workflow.DueSoonEnabled {
		periodicJobs = append(periodicJobs, NewDueSoonCheckerPeriodicJob(cfg.Workflow.DueSoonSchedule, logger))
	}
	if cfg.Workflow != nil && cfg.Workflow.TaskDigestEnabled {
		periodicJobs = append(periodicJobs, NewWorkflowTaskDigestPeriodicJob(cfg.Workflow.TaskDigestSchedule, logger))
	}
	return periodicJobs
}

func buildRiverConfig(cfg *config.WorkerConfig, workers *river.Workers, periodicJobs []*river.PeriodicJob) river.Config {
	return river.Config{
		Queues: map[string]river.QueueConfig{
			"email": {
				MaxWorkers: cfg.Workers,
			},
			"digest": {
				MaxWorkers: 1,
			},
			"scheduler": {
				MaxWorkers: 1,
			},
			"workflow": {
				MaxWorkers: 2,
			},
			"steps": {
				MaxWorkers: 10,
			},
		},
		Workers:      workers,
		PeriodicJobs: periodicJobs,
	}
}

// EnqueueWorkflowTaskAssigned enqueues a workflow-task-assigned notification email job.
// Implements the workflow.NotificationEnqueuer interface.
func (s *Service) EnqueueWorkflowTaskAssigned(ctx context.Context, stepExecution *workflows.StepExecution) error {
	if !s.config.Enabled || s.client == nil {
		return nil
	}

	if stepExecution == nil {
		return nil
	}

	// Only enqueue for user or email-type assignees
	if (stepExecution.AssignedToType != workflows.AssignmentTypeUser.String() &&
		stepExecution.AssignedToType != workflows.AssignmentTypeEmail.String()) ||
		stepExecution.AssignedToID == "" {
		return nil
	}

	// Reload with full nested relations so title fields are always populated,
	// regardless of what the caller had preloaded on the passed-in struct.
	var full workflows.StepExecution
	if err := s.db.WithContext(ctx).
		Preload("WorkflowStepDefinition").
		Preload("WorkflowExecution.WorkflowInstance.WorkflowDefinition").
		First(&full, "id = ?", stepExecution.ID).Error; err == nil {
		stepExecution = &full
	}

	titles := resolveStepTitles(stepExecution)

	args := &WorkflowTaskAssignedArgs{
		AssignedToType:        stepExecution.AssignedToType,
		UserID:                stepExecution.AssignedToID,
		StepExecutionID:       stepExecution.ID.String(),
		StepTitle:             titles.Step,
		WorkflowTitle:         titles.Workflow,
		WorkflowInstanceTitle: titles.Instance,
		StepURL:               "",
		DueDate:               stepExecution.DueDate,
	}

	_, err := s.client.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptionsForWorkflowTaskAssignedNotification()},
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue workflow-task-assigned job: %w", err)
	}

	return nil
}

// EnqueueWorkflowExecutionFailed enqueues a workflow-execution-failed notification email job.
// Implements the workflow.NotificationEnqueuer interface.
func (s *Service) EnqueueWorkflowExecutionFailed(ctx context.Context, execution *workflows.WorkflowExecution) error {
	if !s.config.Enabled || s.client == nil {
		return nil
	}

	if execution == nil || execution.ID == nil {
		return nil
	}

	args := &WorkflowExecutionFailedArgs{
		WorkflowExecutionID: execution.ID.String(),
	}

	_, err := s.client.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptionsForWorkflowNotification()},
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue workflow-execution-failed job: %w", err)
	}

	return nil
}

// EnqueueSendEmail enqueues a send email job
func (s *Service) EnqueueSendEmail(ctx context.Context, args *SendEmailArgs) error {
	if !s.config.Enabled {
		return fmt.Errorf("worker service is disabled")
	}

	if s.client == nil {
		return fmt.Errorf("worker client is not initialized")
	}

	// Use configured queue or default to "email"
	queue := s.config.Queue
	if queue == "" {
		queue = "email"
	}

	// Use configured retry policy or default to 5 attempts
	maxAttempts := s.config.RetryPolicy.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 5
	}

	// Use InsertMany which doesn't require a transaction
	_, err := s.client.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptionsWithRetry(queue, maxAttempts)},
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue send email job: %w", err)
	}
	return nil
}

// EnqueueSendEmailFrom enqueues a send email from provider job
func (s *Service) EnqueueSendEmailFrom(ctx context.Context, args *SendEmailFromArgs) error {
	if !s.config.Enabled {
		return fmt.Errorf("worker service is disabled")
	}

	if s.client == nil {
		return fmt.Errorf("worker client is not initialized")
	}

	// Use configured queue or default to "email"
	queue := s.config.Queue
	if queue == "" {
		queue = "email"
	}

	// Use configured retry policy or default to 5 attempts
	maxAttempts := s.config.RetryPolicy.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 5
	}

	// Use InsertMany which doesn't require a transaction
	_, err := s.client.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptionsWithRetry(queue, maxAttempts)},
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue send email from job: %w", err)
	}
	return nil
}
