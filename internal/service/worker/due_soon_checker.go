package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"gorm.io/gorm"
)

// DueSoonCheckerArgs represents the arguments for the periodic due-soon checker job
type DueSoonCheckerArgs struct{}

// Kind returns the job kind for River
func (DueSoonCheckerArgs) Kind() string { return "workflow_due_soon_checker" }

// Timeout returns the timeout for the due-soon checker job
func (DueSoonCheckerArgs) Timeout() time.Duration { return 5 * time.Minute }

// DueSoonCheckerWorker scans for step executions due tomorrow and enqueues reminder emails
type DueSoonCheckerWorker struct {
	db     *gorm.DB
	client RiverInserter
	logger Logger
}

// RiverInserter is the minimal interface for inserting River jobs
type RiverInserter interface {
	InsertMany(ctx context.Context, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error)
}

// NewDueSoonCheckerWorker creates a new DueSoonCheckerWorker
func NewDueSoonCheckerWorker(db *gorm.DB, client RiverInserter, logger Logger) *DueSoonCheckerWorker {
	return &DueSoonCheckerWorker{
		db:     db,
		client: client,
		logger: logger,
	}
}

// Work scans for step executions due in ~24 hours and enqueues WorkflowTaskDueSoonArgs jobs
func (w *DueSoonCheckerWorker) Work(ctx context.Context, job *river.Job[DueSoonCheckerArgs]) error {
	now := time.Now()
	windowStart := now.Add(23 * time.Hour)
	windowEnd := now.Add(25 * time.Hour)

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

		stepTitle := ""
		workflowTitle := ""
		workflowInstanceTitle := ""
		if step.WorkflowStepDefinition != nil {
			stepTitle = step.WorkflowStepDefinition.Name
		}
		if step.WorkflowExecution != nil && step.WorkflowExecution.WorkflowInstance != nil {
			if step.WorkflowExecution.WorkflowInstance.WorkflowDefinition != nil {
				workflowTitle = step.WorkflowExecution.WorkflowInstance.WorkflowDefinition.Name
			}
			workflowInstanceTitle = step.WorkflowExecution.WorkflowInstance.Name
		}

		args := WorkflowTaskDueSoonArgs{
			UserID:                step.AssignedToID,
			StepExecutionID:       step.ID.String(),
			StepTitle:             stepTitle,
			WorkflowTitle:         workflowTitle,
			WorkflowInstanceTitle: workflowInstanceTitle,
			StepURL:               "",
			DueDate:               *step.DueDate,
		}
		params = append(params, river.InsertManyParams{
			Args:       args,
			InsertOpts: JobInsertOptionsForWorkflowNotification(),
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
