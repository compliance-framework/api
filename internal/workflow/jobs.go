package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
)

// Job types for workflow processing
const (
	JobTypeExecuteWorkflow   = "execute_workflow"
	JobTypeScheduleWorkflows = "schedule_workflows"
)

// ExecuteWorkflowArgs represents the arguments for executing a workflow
type ExecuteWorkflowArgs struct {
	WorkflowExecutionID uuid.UUID `json:"workflow_execution_id"`
	TriggeredBy         string    `json:"triggered_by"`
	TriggeredByID       string    `json:"triggered_by_id"`
}

// ScheduleWorkflowsArgs represents the arguments for the periodic scheduler job
type ScheduleWorkflowsArgs struct {
	// No arguments needed for the periodic scheduler job
}

// Kind returns the job kind for River
func (ExecuteWorkflowArgs) Kind() string { return JobTypeExecuteWorkflow }

// Kind returns the job kind for River
func (ScheduleWorkflowsArgs) Kind() string { return JobTypeScheduleWorkflows }

// Timeout returns the timeout for workflow execution jobs
func (ExecuteWorkflowArgs) Timeout() time.Duration {
	return 30 * time.Minute // Workflows can take longer
}

// WorkflowExecutionWorker handles workflow execution jobs
type WorkflowExecutionWorker struct {
	executor            *DAGExecutor
	evidenceIntegration *EvidenceIntegration
	logger              *zap.SugaredLogger
}

// NewWorkflowExecutionWorker creates a new WorkflowExecutionWorker
func NewWorkflowExecutionWorker(executor *DAGExecutor, evidenceIntegration *EvidenceIntegration, logger *zap.SugaredLogger) *WorkflowExecutionWorker {
	return &WorkflowExecutionWorker{
		executor:            executor,
		evidenceIntegration: evidenceIntegration,
		logger:              logger,
	}
}

// Work is the River work function for initializing workflows
func (w *WorkflowExecutionWorker) Work(ctx context.Context, job *river.Job[ExecuteWorkflowArgs]) error {
	args := job.Args

	w.logger.Infow("Processing workflow initialization job",
		"job_id", job.ID,
		"workflow_execution_id", args.WorkflowExecutionID,
		"triggered_by", args.TriggeredBy,
	)

	// Initialize the workflow (create step executions with proper blocked/pending status)
	err := w.executor.InitializeWorkflow(ctx, &args.WorkflowExecutionID)
	if err != nil {
		w.logger.Errorw("Failed to initialize workflow",
			"job_id", job.ID,
			"workflow_execution_id", args.WorkflowExecutionID,
			"error", err,
		)
		return fmt.Errorf("failed to initialize workflow: %w", err)
	}

	// Create the workflow execution evidence stream immediately when workflow starts
	if w.evidenceIntegration != nil {
		_, err := w.evidenceIntegration.GetOrCreateExecutionStream(ctx, &args.WorkflowExecutionID)
		if err != nil {
			w.logger.Warnw("Failed to create workflow execution evidence stream",
				"job_id", job.ID,
				"workflow_execution_id", args.WorkflowExecutionID,
				"error", err,
			)
			// Don't fail the workflow initialization for evidence stream creation issues
		} else {
			w.logger.Infow("Workflow execution evidence stream created",
				"job_id", job.ID,
				"workflow_execution_id", args.WorkflowExecutionID,
			)
		}
	}

	w.logger.Infow("Workflow initialized successfully - ready for user-driven execution",
		"job_id", job.ID,
		"workflow_execution_id", args.WorkflowExecutionID,
	)

	return nil
}

// JobInsertOptionsForWorkflow returns insert options for workflow execution jobs
func JobInsertOptionsForWorkflow() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "workflow",
		MaxAttempts: 3, // Retry up to 3 times for workflows
		Priority:    1, // Higher priority for workflow jobs
	}
}

// JobInsertOptionsForScheduler returns insert options for the scheduler job
func JobInsertOptionsForScheduler() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "scheduler",
		MaxAttempts: 3,
		Priority:    1,
	}
}
