package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// CronScheduler implements Scheduler using robfig/cron
type CronScheduler struct {
	cron   *cron.Cron
	logger *zap.SugaredLogger
	jobs   map[string]Job
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

// NewCronScheduler creates a new cron-based scheduler
func NewCronScheduler(logger *zap.SugaredLogger) *CronScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &CronScheduler{
		cron:   cron.New(cron.WithSeconds()),
		logger: logger,
		jobs:   make(map[string]Job),
		ctx:    ctx,
		cancel: cancel,
	}
}

// ParseCronNext parses a cron expression and returns the next scheduled time
// Supports 6-field cron syntax (with seconds) and descriptors like @weekly, @daily, etc.
// Format: second minute hour day month weekday
//
//	@weekly	= Monday 00:00:00 UTC
func ParseCronNext(cronExpr string, from time.Time) (time.Time, error) {
	// Use same parser as CronScheduler - supports seconds (6-field cron)
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	schedule, err := parser.Parse(cronExpr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse cron expression %q: %w", cronExpr, err)
	}
	return schedule.Next(from), nil
}

// Schedule adds a job to run on the given schedule
func (s *CronScheduler) Schedule(schedule Schedule, job Job) error {
	var cronExpr string
	switch schedule {
	case ScheduleDaily:
		cronExpr = "0 0 0 * * *" // Every day at midnight
	case ScheduleWeekly:
		cronExpr = "0 0 0 * * 0" // Every Sunday at midnight
	case ScheduleMonthly:
		cronExpr = "0 0 0 1 * *" // First day of every month at midnight
	default:
		return fmt.Errorf("unknown schedule: %s", schedule)
	}
	return s.ScheduleCron(cronExpr, job)
}

// ScheduleCron adds a job with a custom cron expression
// Cron format: second minute hour day month weekday (6 fields with seconds support)
// Examples:
//
//	"0 0 * * * *"     - Every hour at minute 0
//	"0 */5 * * * *"   - Every 5 minutes
//	"0 0 0 * * *"     - Every day at midnight
//	"@hourly"         - Every hour (equivalent to "0 0 * * * *")
func (s *CronScheduler) ScheduleCron(cronExpr string, job Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.jobs[job.Name()]; exists {
		return fmt.Errorf("job %q already registered", job.Name())
	}

	_, err := s.cron.AddFunc(cronExpr, func() {
		s.logger.Debugw("Starting scheduled job", "job", job.Name())
		if err := job.Execute(s.ctx); err != nil {
			s.logger.Errorw("Scheduled job failed", "job", job.Name(), "error", err)
		} else {
			s.logger.Debugw("Scheduled job completed", "job", job.Name())
		}
	})
	if err != nil {
		return fmt.Errorf("failed to schedule job %q: %w", job.Name(), err)
	}

	s.jobs[job.Name()] = job
	s.logger.Debugw("Job scheduled", "job", job.Name(), "cron", cronExpr)
	return nil
}

// Start begins processing scheduled jobs
func (s *CronScheduler) Start() {
	s.logger.Debug("Starting scheduler")
	s.cron.Start()
}

// Stop gracefully stops the scheduler
func (s *CronScheduler) Stop() context.Context {
	s.logger.Debug("Stopping scheduler")

	// Cancel the context to signal running jobs to stop
	s.cancel()

	// Stop the cron scheduler
	return s.cron.Stop()
}

// RunNow executes a job immediately by name
func (s *CronScheduler) RunNow(ctx context.Context, jobName string) error {
	s.mu.RLock()
	job, exists := s.jobs[jobName]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("job %q not found", jobName)
	}

	s.logger.Debugw("Running job manually", "job", jobName)
	return job.Execute(ctx)
}

// ListJobs returns all registered job names
func (s *CronScheduler) ListJobs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	names := make([]string, 0, len(s.jobs))
	for name := range s.jobs {
		names = append(names, name)
	}
	return names
}
