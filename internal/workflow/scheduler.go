package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
)

// WorkflowSchedulerWorker handles the periodic scheduling of workflows
type WorkflowSchedulerWorker struct {
	manager                 *Manager
	workflowInstanceService WorkflowInstanceServiceInterface
	overdueService          *OverdueService
	overdueCheckEnabled     bool
	logger                  *zap.SugaredLogger
	defaultGracePeriod      int
}

// NewWorkflowSchedulerWorker creates a new WorkflowSchedulerWorker
func NewWorkflowSchedulerWorker(
	manager *Manager,
	workflowInstanceService WorkflowInstanceServiceInterface,
	overdueService *OverdueService,
	overdueCheckEnabled bool,
	logger *zap.SugaredLogger,
	defaultGracePeriod int,
) *WorkflowSchedulerWorker {
	return &WorkflowSchedulerWorker{
		manager:                 manager,
		workflowInstanceService: workflowInstanceService,
		overdueService:          overdueService,
		overdueCheckEnabled:     overdueCheckEnabled,
		logger:                  logger,
		defaultGracePeriod:      defaultGracePeriod,
	}
}

// GeneratePeriodLabel generates a label for the period based on cadence and time
func GeneratePeriodLabel(cadence string, t time.Time) string {
	cadenceType := workflows.CadenceType(cadence)

	// Handle custom cron expressions - use timestamp format
	if cadenceType.IsCron() {
		return t.Format("2006-01-02T15:04:05")
	}

	switch cadenceType {
	case workflows.CadenceDaily:
		return t.Format("2006-01-02")
	case workflows.CadenceWeekly:
		year, week := t.ISOWeek()
		return fmt.Sprintf("%d-W%02d", year, week)
	case workflows.CadenceMonthly:
		return t.Format("2006-01")
	case workflows.CadenceQuarterly:
		month := t.Month()
		quarter := (month-1)/3 + 1
		return fmt.Sprintf("Q%d-%d", quarter, t.Year())
	case workflows.CadenceAnnually:
		return t.Format("2006")
	default:
		// Fallback for unknown cadences - use daily format
		return t.Format("2006-01-02")
	}
}

// CalculateDueDate calculates the due date based on schedule time and grace period
func CalculateDueDate(scheduledTime time.Time, gracePeriodDays int) time.Time {
	return scheduledTime.AddDate(0, 0, gracePeriodDays)
}

// Work is the River work function for scheduling workflows
func (w *WorkflowSchedulerWorker) Work(ctx context.Context, job *river.Job[ScheduleWorkflowsArgs]) error {
	w.logger.Infow("Processing workflow scheduler job",
		"job_id", job.ID,
	)

	// 1. Get due instances
	dueInstances, err := w.workflowInstanceService.GetDueInstances(ctx)
	if err != nil {
		w.logger.Errorw("Failed to get due workflow instances",
			"job_id", job.ID,
			"error", err,
		)
		return fmt.Errorf("failed to get due workflow instances: %w", err)
	}

	w.logger.Infow("Found due workflow instances",
		"count", len(dueInstances),
	)

	processedCount := 0
	errorCount := 0

	// 2. Process each instance
	for _, instance := range dueInstances {
		// Calculate period label for the current time
		// We use the NextScheduledAt time if available, otherwise Now
		refTime := time.Now()
		if instance.NextScheduledAt != nil {
			refTime = *instance.NextScheduledAt
		}

		periodLabel := GeneratePeriodLabel(instance.Cadence, refTime)

		// Determine grace period
		gracePeriod := ResolveGraceDays(&instance, w.defaultGracePeriod)

		// Calculate due date
		// Due date is based on the scheduled time (when it should have run), not necessarily now
		// If we are running late, the due date should still be relative to the scheduled time
		dueDate := CalculateDueDate(refTime, gracePeriod)

		// Start workflow execution
		options := StartWorkflowOptions{
			TriggeredBy:   workflows.TriggerScheduled.String(),
			TriggeredByID: "workflow-scheduler",
			PeriodLabel:   periodLabel,
			DueDate:       &dueDate,
		}

		executionID, err := w.manager.StartWorkflowExecution(ctx, instance.ID, options)
		if err != nil {
			if errors.Is(err, ErrWorkflowExecutionAlreadyExists) {
				w.logger.Infow("Skipping already executed workflow instance for this period",
					"instance_id", instance.ID,
					"period_label", periodLabel,
				)

				// Still need to update next schedule if it's in the past
				if err := w.workflowInstanceService.AdvanceSchedule(ctx, instance.ID); err != nil {
					w.logger.Errorw("Failed to update schedule for skipped instance",
						"instance_id", instance.ID,
						"error", err,
					)
				}
				continue
			}
			w.logger.Errorw("Failed to start workflow execution",
				"instance_id", instance.ID,
				"error", err,
			)
			errorCount++
			continue
		}

		// Update next schedule
		if err := w.workflowInstanceService.AdvanceSchedule(ctx, instance.ID); err != nil {
			w.logger.Errorw("Failed to update next schedule",
				"instance_id", instance.ID,
				"execution_id", executionID,
				"error", err,
			)
			// Don't fail the whole job, just log error
			errorCount++
		}

		// Update last executed
		// Note: Ideally this would be done by the service when creating execution,
		// but we might need to be explicit here if not

		processedCount++

		w.logger.Infow("Scheduled workflow execution",
			"instance_id", instance.ID,
			"execution_id", executionID,
			"period_label", periodLabel,
		)
	}

	w.logger.Infow("Workflow scheduler job completed",
		"processed", processedCount,
		"errors", errorCount,
	)

	if w.overdueCheckEnabled && w.overdueService != nil {
		if _, err := w.overdueService.CheckOverdueSteps(ctx); err != nil {
			w.logger.Errorw("Failed to check overdue steps", "error", err)
		}
		if _, err := w.overdueService.CheckOverdueExecutions(ctx); err != nil {
			w.logger.Errorw("Failed to check overdue executions", "error", err)
		}
		if _, err := w.overdueService.CheckFailedExecutions(ctx); err != nil {
			w.logger.Errorw("Failed to check failed executions", "error", err)
		}
	}

	return nil
}
