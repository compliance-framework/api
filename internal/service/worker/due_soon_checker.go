package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DueSoonCheckerArgs represents the arguments for the periodic due-soon checker job
type DueSoonCheckerArgs struct{}

// Kind returns the job kind for River
func (DueSoonCheckerArgs) Kind() string { return "workflow_due_soon_checker" }

// Timeout returns the timeout for the due-soon checker job
func (DueSoonCheckerArgs) Timeout() time.Duration { return 5 * time.Minute }

// DueSoonCheckerWorker scans for step executions due in a week and enqueues reminder emails
type DueSoonCheckerWorker struct {
	db     *gorm.DB
	client workflow.RiverClient
	logger *zap.SugaredLogger
}

// NewDueSoonCheckerWorker creates a new DueSoonCheckerWorker
func NewDueSoonCheckerWorker(db *gorm.DB, client workflow.RiverClient, logger *zap.SugaredLogger) *DueSoonCheckerWorker {
	return &DueSoonCheckerWorker{
		db:     db,
		client: client,
		logger: logger,
	}
}

// Work scans for step executions due in ~1 week and enqueues WorkflowTaskDueSoonArgs jobs
func (w *DueSoonCheckerWorker) Work(ctx context.Context, job *river.Job[DueSoonCheckerArgs]) error {
	now := time.Now()
	windowStart := now
	windowEnd := now.Add(7 * 24 * time.Hour)

	var steps []workflows.StepExecution
	if err := w.db.WithContext(ctx).
		Preload("WorkflowExecution.WorkflowInstance.WorkflowDefinition").
		Preload("WorkflowStepDefinition").
		Where("status IN ? AND due_date IS NOT NULL AND due_date >= ? AND due_date <= ? AND assigned_to_type = ? AND assigned_to_id != ''",
			[]string{
				workflows.StepStatusPending.String(),
				workflows.StepStatusInProgress.String(),
			},
			windowStart,
			windowEnd,
			workflows.AssignmentTypeUser.String(),
		).
		Find(&steps).Error; err != nil {
		return fmt.Errorf("due-soon checker: failed to query steps: %w", err)
	}

	if len(steps) == 0 {
		w.logger.Infow("DueSoonCheckerWorker: no steps due soon", "window_start", windowStart, "window_end", windowEnd)
		return nil
	}

	params := make([]river.InsertManyParams, 0, len(steps))
	for i := range steps {
		step := &steps[i]
		if step.DueDate == nil {
			continue
		}

		titles := resolveStepTitles(step)

		args := WorkflowTaskDueSoonArgs{
			UserID:                step.AssignedToID,
			StepExecutionID:       step.ID.String(),
			StepTitle:             titles.Step,
			WorkflowTitle:         titles.Workflow,
			WorkflowInstanceTitle: titles.Instance,
			StepURL:               "",
			DueDate:               *step.DueDate,
		}
		insertOpts := JobInsertOptionsForWorkflowNotification()
		insertOpts.UniqueOpts = river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 24 * time.Hour,
		}
		params = append(params, river.InsertManyParams{
			Args:       args,
			InsertOpts: insertOpts,
		})
	}

	if len(params) == 0 {
		return nil
	}

	if _, err := w.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("due-soon checker: failed to enqueue reminder jobs: %w", err)
	}

	w.logger.Infow("DueSoonCheckerWorker: enqueued due-soon reminders", "count", len(params))
	return nil
}
