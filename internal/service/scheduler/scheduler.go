package scheduler

import (
	"context"
)

// Job represents a scheduled job that can be executed
type Job interface {
	// Name returns the unique name of the job
	Name() string
	// Execute runs the job
	Execute(ctx context.Context) error
}

// Schedule represents when a job should run
type Schedule string

const (
	// ScheduleDaily runs the job once per day at midnight UTC
	ScheduleDaily Schedule = "@daily"
	// ScheduleWeekly runs the job once per week on Sunday at midnight UTC
	ScheduleWeekly Schedule = "@weekly"
	// ScheduleMonthly runs the job once per month on the 1st at midnight UTC
	ScheduleMonthly Schedule = "@monthly"
)

// Scheduler is the interface for scheduling and managing jobs
// This abstraction allows swapping the underlying scheduler implementation
// (e.g., from built-in cron to an external scheduler like Temporal or a message queue)
type Scheduler interface {
	// Schedule adds a job to run on the given schedule
	Schedule(schedule Schedule, job Job) error
	// ScheduleCron adds a job with a custom cron expression
	ScheduleCron(cronExpr string, job Job) error
	// Start begins processing scheduled jobs
	Start()
	// Stop gracefully stops the scheduler
	Stop() context.Context
	// RunNow executes a job immediately by name (useful for testing/manual triggers)
	RunNow(ctx context.Context, jobName string) error
	// ListJobs returns all registered job names
	ListJobs() []string
}
