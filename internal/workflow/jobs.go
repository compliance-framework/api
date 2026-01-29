package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
)

// Logger interface for logging
type Logger interface {
	Infow(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
}

// Job types for workflow processing
const (
	JobTypeExecuteWorkflow = "execute_workflow"
	JobTypeExecuteStep     = "execute_step"
)

// ExecuteWorkflowArgs represents the arguments for executing a workflow
type ExecuteWorkflowArgs struct {
	WorkflowExecutionID uuid.UUID `json:"workflow_execution_id"`
	TriggeredBy         string    `json:"triggered_by"`
	TriggeredByID       string    `json:"triggered_by_id"`
}

// ExecuteStepArgs represents the arguments for executing a single workflow step
type ExecuteStepArgs struct {
	WorkflowExecutionID      uuid.UUID `json:"workflow_execution_id"`
	WorkflowStepDefinitionID uuid.UUID `json:"workflow_step_definition_id"`
	StepExecutionID          uuid.UUID `json:"step_execution_id"`
}

// Kind returns the job kind for River
func (ExecuteWorkflowArgs) Kind() string { return JobTypeExecuteWorkflow }

// Kind returns the job kind for River
func (ExecuteStepArgs) Kind() string { return JobTypeExecuteStep }

// Timeout returns the timeout for workflow execution jobs
func (ExecuteWorkflowArgs) Timeout() time.Duration {
	return 30 * time.Minute // Workflows can take longer
}

// Timeout returns the timeout for step execution jobs
func (ExecuteStepArgs) Timeout() time.Duration {
	return 5 * time.Minute // Individual steps should be faster
}

// WorkflowExecutionWorker handles workflow execution jobs
type WorkflowExecutionWorker struct {
	executor *DAGExecutor
	logger   Logger
}

// NewWorkflowExecutionWorker creates a new WorkflowExecutionWorker
func NewWorkflowExecutionWorker(executor *DAGExecutor, logger Logger) *WorkflowExecutionWorker {
	return &WorkflowExecutionWorker{
		executor: executor,
		logger:   logger,
	}
}

// Work is the River work function for executing workflows
func (w *WorkflowExecutionWorker) Work(ctx context.Context, job *river.Job[ExecuteWorkflowArgs]) error {
	args := job.Args

	w.logger.Infow("Processing workflow execution job",
		"job_id", job.ID,
		"workflow_execution_id", args.WorkflowExecutionID,
		"triggered_by", args.TriggeredBy,
	)

	// Execute the workflow using the DAG executor
	result, err := w.executor.ExecuteWorkflow(ctx, &args.WorkflowExecutionID)
	if err != nil {
		w.logger.Errorw("Failed to execute workflow",
			"job_id", job.ID,
			"workflow_execution_id", args.WorkflowExecutionID,
			"error", err,
		)
		return fmt.Errorf("failed to execute workflow: %w", err)
	}

	if !result.Success {
		w.logger.Errorw("Workflow execution failed",
			"job_id", job.ID,
			"workflow_execution_id", args.WorkflowExecutionID,
			"completed_steps", result.CompletedSteps,
			"failed_steps", result.FailedSteps,
			"errors", result.Errors,
		)
		return fmt.Errorf("workflow execution failed: %d steps failed", result.FailedSteps)
	}

	w.logger.Infow("Workflow executed successfully",
		"job_id", job.ID,
		"workflow_execution_id", args.WorkflowExecutionID,
		"completed_steps", result.CompletedSteps,
		"execution_time", result.ExecutionTime,
	)

	return nil
}

// StepExecutionWorker handles individual step execution jobs
type StepExecutionWorker struct {
	stepExecutionService StepExecutionServiceInterface
	logger               Logger
}

// NewStepExecutionWorker creates a new StepExecutionWorker
func NewStepExecutionWorker(stepExecutionService StepExecutionServiceInterface, logger Logger) *StepExecutionWorker {
	return &StepExecutionWorker{
		stepExecutionService: stepExecutionService,
		logger:               logger,
	}
}

// Work is the River work function for executing individual steps
func (w *StepExecutionWorker) Work(ctx context.Context, job *river.Job[ExecuteStepArgs]) error {
	args := job.Args

	w.logger.Infow("Processing step execution job",
		"job_id", job.ID,
		"workflow_execution_id", args.WorkflowExecutionID,
		"step_definition_id", args.WorkflowStepDefinitionID,
		"step_execution_id", args.StepExecutionID,
	)

	// Get the step execution
	_, err := w.stepExecutionService.GetByID(&args.StepExecutionID)
	if err != nil {
		w.logger.Errorw("Failed to get step execution",
			"job_id", job.ID,
			"step_execution_id", args.StepExecutionID,
			"error", err,
		)
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	// Update status to in_progress
	if err := w.stepExecutionService.UpdateStatus(&args.StepExecutionID, "in_progress"); err != nil {
		w.logger.Errorw("Failed to update step status to in_progress",
			"job_id", job.ID,
			"step_execution_id", args.StepExecutionID,
			"error", err,
		)
		return fmt.Errorf("failed to update step status: %w", err)
	}

	// Simulate step execution (this would be replaced with actual step logic)
	// For now, we'll just mark it as completed
	time.Sleep(100 * time.Millisecond) // Simulate work

	// Update status to completed
	if err := w.stepExecutionService.UpdateStatus(&args.StepExecutionID, "completed"); err != nil {
		w.logger.Errorw("Failed to update step status to completed",
			"job_id", job.ID,
			"step_execution_id", args.StepExecutionID,
			"error", err,
		)
		return fmt.Errorf("failed to update step status: %w", err)
	}

	w.logger.Infow("Step executed successfully",
		"job_id", job.ID,
		"step_execution_id", args.StepExecutionID,
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

// JobInsertOptionsForStep returns insert options for step execution jobs
func JobInsertOptionsForStep() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "steps",
		MaxAttempts: 5, // More retries for individual steps
		Priority:    2, // Lower priority than workflow jobs
	}
}

// WorkflowWorkers returns workflow workers with dependencies injected
func WorkflowWorkers(
	executor *DAGExecutor,
	stepExecutionService StepExecutionServiceInterface,
	logger Logger,
) *river.Workers {
	workers := river.NewWorkers()

	// Create worker instances with dependencies
	workflowExecutionWorker := NewWorkflowExecutionWorker(executor, logger)
	stepExecutionWorker := NewStepExecutionWorker(stepExecutionService, logger)

	// Register workers with their Work methods
	river.AddWorker(workers, river.WorkFunc(workflowExecutionWorker.Work))
	river.AddWorker(workers, river.WorkFunc(stepExecutionWorker.Work))

	return workers
}
