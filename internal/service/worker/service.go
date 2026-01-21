package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// contextKey is a private type for context keys to prevent collisions
type contextKey string

const (
	emailServiceKey  contextKey = "emailService"
	loggerKey        contextKey = "logger"
	digestServiceKey contextKey = "digestService"
)

// Service manages the River client and workers
type Service struct {
	client    *river.Client[pgx.Tx]
	config    *config.WorkerConfig
	db        *gorm.DB
	emailSvc  *email.Service
	digestSvc DigestService
	logger    *zap.SugaredLogger
	started   bool
	pgxPool   *pgxpool.Pool
	digestCfg *config.Config
}

// NewService creates a new worker service
func NewService(
	cfg *config.WorkerConfig,
	db *gorm.DB,
	emailSvc *email.Service,
	logger *zap.SugaredLogger,
) (*Service, error) {
	return NewServiceWithDigest(cfg, db, emailSvc, nil, nil, logger)
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
	var pgxPool *pgxpool.Pool
	// Since GORM's ConnPool doesn't directly expose pgxpool.Pool,
	// we need to create a new pool from the DSN
	dsn := db.Dialector.(*postgres.Dialector).DSN
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgx pool: %w", err)
	}
	pgxPool = pool

	// Register workers
	workers := Workers()

	// Configure periodic jobs
	var periodicJobs []*river.PeriodicJob
	if digestCfg != nil && digestCfg.DigestEnabled {
		periodicJobs = append(periodicJobs, NewDigestPeriodicJob(digestCfg.DigestSchedule, logger))
	}

	// Create River client with pgxv5 driver
	riverConfig := river.Config{
		Queues: map[string]river.QueueConfig{
			"email": {
				MaxWorkers: cfg.Workers,
			},
			"digest": {
				MaxWorkers: 1, // Only one digest worker to avoid duplicates
			},
		},
		Workers:      workers,
		PeriodicJobs: periodicJobs,
	}

	// Create the client
	client, err := river.NewClient(riverpgxv5.New(pgxPool), &riverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create River client: %w", err)
	}

	service := &Service{
		client:    client,
		config:    cfg,
		db:        db,
		emailSvc:  emailSvc,
		digestSvc: digestSvc,
		digestCfg: digestCfg,
		logger:    logger,
		started:   false,
		pgxPool:   pgxPool,
	}

	return service, nil
}

// Start starts the worker service
func (s *Service) Start(ctx context.Context) error {
	if !s.config.Enabled {
		s.logger.Info("Worker service is disabled, not starting")
		return nil
	}

	if s.started {
		s.logger.Warn("Worker service is already started")
		return nil
	}

	s.logger.Infow("Starting worker service",
		"workers", s.config.Workers,
		"queue", s.config.Queue,
	)

	// Create a new context with services for workers
	workerCtx := context.WithValue(ctx, emailServiceKey, s.emailSvc)
	workerCtx = context.WithValue(workerCtx, loggerKey, s.logger)
	if s.digestSvc != nil {
		workerCtx = context.WithValue(workerCtx, digestServiceKey, s.digestSvc)
	}

	// Start the workers with injected context
	if err := s.client.Start(workerCtx); err != nil {
		return fmt.Errorf("failed to start River client: %w", err)
	}

	s.started = true
	s.logger.Info("Worker service started successfully")
	return nil
}

// Stop stops the worker service
func (s *Service) Stop(ctx context.Context) error {
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
	// Parse the cron schedule using robfig/cron
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	schedule, err := parser.Parse(cronSchedule)
	if err != nil {
		logger.Errorw("Failed to parse digest cron schedule, using default @weekly", "schedule", cronSchedule, "error", err)
		// Fallback to weekly schedule
		schedule, _ = parser.Parse("@weekly")
	}

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

// EnqueueSendEmail enqueues a send email job
func (s *Service) EnqueueSendEmail(ctx context.Context, args *SendEmailArgs) error {
	if !s.config.Enabled {
		return fmt.Errorf("worker service is disabled")
	}

	// Use InsertMany which doesn't require a transaction
	_, err := s.client.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptions()},
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

	// Use InsertMany which doesn't require a transaction
	_, err := s.client.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptions()},
	})
	if err != nil {
		return fmt.Errorf("failed to enqueue send email from job: %w", err)
	}
	return nil
}
