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
	JobTypeExecuteWorkflow   = "execute_workflow"
	JobTypeExecuteStep       = "execute_step"
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

// ExecuteStepArgs represents the arguments for executing a single workflow step
type ExecuteStepArgs struct {
	WorkflowExecutionID      uuid.UUID `json:"workflow_execution_id"`
	WorkflowStepDefinitionID uuid.UUID `json:"workflow_step_definition_id"`
	StepExecutionID          uuid.UUID `json:"step_execution_id"`
}

// Kind returns the job kind for River
func (ExecuteWorkflowArgs) Kind() string { return JobTypeExecuteWorkflow }

// Kind returns the job kind for River
func (ScheduleWorkflowsArgs) Kind() string { return JobTypeScheduleWorkflows }

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
	executor            *DAGExecutor
	evidenceIntegration *EvidenceIntegration
	logger              Logger
}

// NewWorkflowExecutionWorker creates a new WorkflowExecutionWorker
func NewWorkflowExecutionWorker(executor *DAGExecutor, evidenceIntegration *EvidenceIntegration, logger Logger) *WorkflowExecutionWorker {
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
// NOTE: In Phase 1, steps are manually executed by users via the StepTransitionService.
// This worker is reserved for future automatic step execution (Phase 5).
// For now, it only logs that a step execution was requested but does not auto-complete it.
func (w *StepExecutionWorker) Work(ctx context.Context, job *river.Job[ExecuteStepArgs]) error {
	args := job.Args

	w.logger.Infow("Step execution job received (manual execution mode - no auto-completion)",
		"job_id", job.ID,
		"workflow_execution_id", args.WorkflowExecutionID,
		"step_definition_id", args.WorkflowStepDefinitionID,
		"step_execution_id", args.StepExecutionID,
	)

	// Get the step execution to verify it exists
	stepExec, err := w.stepExecutionService.GetByID(&args.StepExecutionID)
	if err != nil {
		w.logger.Errorw("Failed to get step execution",
			"job_id", job.ID,
			"step_execution_id", args.StepExecutionID,
			"error", err,
		)
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	w.logger.Infow("Step execution verified - awaiting manual user action",
		"job_id", job.ID,
		"step_execution_id", args.StepExecutionID,
		"current_status", stepExec.Status,
	)

	// Phase 1: Manual execution only - users must transition steps via StepTransitionService
	// Phase 5: This worker will handle automatic step execution based on triggers
	// TODO: Implement automatic step execution logic for Phase 5

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

// JobInsertOptionsForScheduler returns insert options for the scheduler job
func JobInsertOptionsForScheduler() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "scheduler",
		MaxAttempts: 3,
		Priority:    1,
	}
}

// // WorkflowWorkers returns workflow workers with dependencies injected
// func WorkflowWorkers(
// 	executor *DAGExecutor,
// 	evidenceIntegration *EvidenceIntegration,
// 	stepExecutionService StepExecutionServiceInterface,
// 	logger Logger,
// ) *river.Workers {
// 	workers := river.NewWorkers()

// 	// Create worker instances with dependencies
// 	workflowExecutionWorker := NewWorkflowExecutionWorker(executor, evidenceIntegration, logger)
// 	stepExecutionWorker := NewStepExecutionWorker(stepExecutionService, logger)

// 	// Register workers with their Work methods
// 	river.AddWorker(workers, river.WorkFunc(workflowExecutionWorker.Work))
// 	river.AddWorker(workers, river.WorkFunc(stepExecutionWorker.Work))

// 	return workers
// }
