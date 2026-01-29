package workflow

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
)

// WorkflowExecutor handles the overall execution of workflows
type WorkflowExecutor struct {
	workflowExecutionService WorkflowExecutionServiceInterface
	stepDefinitionService    WorkflowStepDefinitionServiceInterface
	stepExecutor             *StepExecutor
	evidenceIntegration      *EvidenceIntegration // Optional
	logger                   *log.Logger
}

// NewWorkflowExecutor creates a new workflow executor
func NewWorkflowExecutor(
	workflowExecutionService WorkflowExecutionServiceInterface,
	stepDefinitionService WorkflowStepDefinitionServiceInterface,
	stepExecutor *StepExecutor,
	logger *log.Logger,
) *WorkflowExecutor {
	if logger == nil {
		logger = log.Default()
	}

	return &WorkflowExecutor{
		workflowExecutionService: workflowExecutionService,
		stepDefinitionService:    stepDefinitionService,
		stepExecutor:             stepExecutor,
		logger:                   logger,
	}
}

// SetEvidenceIntegration sets the evidence integration service (optional)
func (we *WorkflowExecutor) SetEvidenceIntegration(evidenceIntegration *EvidenceIntegration) {
	we.evidenceIntegration = evidenceIntegration
	we.stepExecutor.SetEvidenceIntegration(evidenceIntegration)
}

// ExecuteWorkflow executes a workflow with DAG evaluation and parallel step execution
func (we *WorkflowExecutor) ExecuteWorkflow(
	ctx context.Context,
	workflowExecutionID *uuid.UUID,
) (*ExecutionResult, error) {
	we.logger.Printf("Starting workflow execution: %s", workflowExecutionID.String())

	startTime := time.Now()

	// Get workflow execution details
	workflowExecution, err := we.workflowExecutionService.GetByID(workflowExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Get all step definitions for this workflow
	stepDefinitions, err := we.stepDefinitionService.GetByWorkflowDefinitionID(workflowExecution.WorkflowInstance.WorkflowDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step definitions: %w", err)
	}

	if len(stepDefinitions) == 0 {
		return nil, fmt.Errorf("no steps defined for workflow")
	}

	// Create state manager
	stateManager := NewWorkflowStateManager(*workflowExecutionID)

	// Initialize step states
	stepAdapters := we.createStepAdapters(stepDefinitions)
	stateManager.InitializeStepStates(stepAdapters)

	// Update workflow execution status to in_progress
	if err := we.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusInProgress); err != nil {
		return nil, fmt.Errorf("failed to update workflow execution status: %w", err)
	}

	// Execute the workflow
	result, err := we.executeWorkflowSteps(ctx, stateManager, stepDefinitions, workflowExecutionID)
	if err != nil {
		we.logger.Printf("Workflow execution failed: %v", err)

		// Update workflow execution status to failed
		if updateErr := we.workflowExecutionService.Fail(workflowExecutionID, err.Error()); updateErr != nil {
			we.logger.Printf("Failed to update workflow execution status: %v", updateErr)
		}

		return result, err
	}

	// Update workflow execution status to completed
	if err := we.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusCompleted); err != nil {
		we.logger.Printf("Failed to update workflow execution status: %v", err)
	}

	// Add execution completion evidence to stream (if evidence integration is enabled)
	if we.evidenceIntegration != nil {
		if err := we.evidenceIntegration.AddExecutionCompletionEvidence(ctx, workflowExecutionID); err != nil {
			we.logger.Printf("Failed to add execution completion evidence: %v", err)
		}
	}

	result.ExecutionTime = time.Since(startTime)
	we.logger.Printf("Workflow execution completed successfully in %v", result.ExecutionTime)

	return result, nil
}

// executeWorkflowSteps executes all steps in the workflow with dependency resolution
func (we *WorkflowExecutor) executeWorkflowSteps(
	ctx context.Context,
	stateManager *WorkflowStateManager,
	stepDefinitions []workflows.WorkflowStepDefinition,
	workflowExecutionID *uuid.UUID,
) (*ExecutionResult, error) {
	result := &ExecutionResult{
		StepResults: make(map[uuid.UUID]*StepExecutionResult),
		TotalSteps:  len(stepDefinitions),
	}

	executionErrors := make(chan error, len(stepDefinitions))

	// Continue execution until all steps are completed or failed
	for {
		// Find steps that can be executed (dependencies satisfied)
		readySteps := stateManager.GetReadySteps()

		if len(readySteps) == 0 {
			// Check if execution is complete
			if stateManager.IsExecutionComplete() {
				break
			}

			// If no ready steps but execution not complete, wait briefly and check again
			summary := stateManager.GetExecutionSummary()
			if summary.RunningSteps > 0 {
				we.logger.Printf("Waiting for %d running steps to complete", summary.RunningSteps)
				time.Sleep(StepPollInterval)
				continue
			}

			// No running steps and no ready steps - this indicates a deadlock or error
			return nil, fmt.Errorf("workflow execution deadlock: no steps can be executed")
		}

		// Execute ready steps in parallel
		var wg sync.WaitGroup
		for _, stepID := range readySteps {
			wg.Add(1)
			go func(stepDefID uuid.UUID, execID *uuid.UUID) {
				defer wg.Done()

				stepResult, err := we.stepExecutor.ExecuteStepSafe(ctx, *execID, stepDefID, stateManager)
				if err != nil {
					executionErrors <- fmt.Errorf("step %s failed: %w", stepDefID.String(), err)
				} else if stepResult != nil {
					result.StepResults[stepDefID] = stepResult
				}
			}(stepID, workflowExecutionID)
		}

		// Wait for all current batch of steps to complete before finding next ready steps
		wg.Wait()

		// Check for execution errors
		select {
		case err := <-executionErrors:
			we.logger.Printf("Step execution error: %v", err)
			result.Errors = append(result.Errors, err.Error())
		default:
			// No errors
		}
	}

	// Calculate final results
	summary := stateManager.GetExecutionSummary()
	result.CompletedSteps = summary.CompletedSteps
	result.FailedSteps = summary.FailedSteps
	result.Success = summary.FailedSteps == 0 && summary.CompletedSteps == len(stepDefinitions)

	return result, nil
}

// createStepAdapters converts step definitions to adapters
func (we *WorkflowExecutor) createStepAdapters(stepDefinitions []workflows.WorkflowStepDefinition) []WorkflowStepDefinitionInterface {
	adapters := make([]WorkflowStepDefinitionInterface, len(stepDefinitions))

	for i, stepDef := range stepDefinitions {
		// Get dependencies for this step
		dependencies, _ := we.stepDefinitionService.GetDependencies(stepDef.ID)

		// Convert dependencies to UUID slice
		depIDs := make([]uuid.UUID, len(dependencies))
		for j, dep := range dependencies {
			depIDs[j] = *dep.ID
		}

		adapters[i] = &SimpleStepDefinitionAdapter{
			ID:           *stepDef.ID,
			Dependencies: depIDs,
		}
	}

	return adapters
}

// CancelExecution cancels a running workflow execution
func (we *WorkflowExecutor) CancelExecution(ctx context.Context, workflowExecutionID *uuid.UUID) error {
	we.logger.Printf("Cancelling workflow execution: %s", workflowExecutionID.String())

	// Update workflow execution status to cancelled
	if err := we.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusCancelled); err != nil {
		return fmt.Errorf("failed to update workflow execution status: %w", err)
	}

	// Cancel all running step executions
	stepExecutions, err := we.stepExecutor.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step executions: %w", err)
	}

	for _, stepExec := range stepExecutions {
		if stepExec.Status == StatusInProgress {
			if err := we.stepExecutor.CancelStep(stepExec.ID); err != nil {
				we.logger.Printf("Failed to cancel step execution %s: %v", stepExec.ID.String(), err)
			}
		}
	}

	we.logger.Printf("Workflow execution cancelled: %s", workflowExecutionID.String())
	return nil
}

// GetExecutionStatus returns the current status of a workflow execution
func (we *WorkflowExecutor) GetExecutionStatus(workflowExecutionID *uuid.UUID) (*ExecutionState, error) {
	// Get all step executions for this workflow
	stepExecutions, err := we.stepExecutor.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step executions: %w", err)
	}

	// Build execution state from step executions
	state := &ExecutionState{
		WorkflowExecutionID: *workflowExecutionID,
		StepStates:          make(map[uuid.UUID]*StepState),
		CompletedSteps:      make(map[uuid.UUID]bool),
		FailedSteps:         make(map[uuid.UUID]bool),
		RunningSteps:        make(map[uuid.UUID]bool),
		BlockedSteps:        make(map[uuid.UUID]bool),
	}

	for _, stepExec := range stepExecutions {
		stepState := &StepState{
			StepDefinitionID: *stepExec.WorkflowStepDefinitionID,
			Status:           stepExec.Status,
			StartedAt:        stepExec.StartedAt,
			CompletedAt:      stepExec.CompletedAt,
			FailureReason:    stepExec.FailureReason,
		}

		state.StepStates[*stepExec.WorkflowStepDefinitionID] = stepState

		switch stepExec.Status {
		case StatusCompleted:
			state.CompletedSteps[*stepExec.WorkflowStepDefinitionID] = true
		case StatusFailed:
			state.FailedSteps[*stepExec.WorkflowStepDefinitionID] = true
		case StatusInProgress:
			state.RunningSteps[*stepExec.WorkflowStepDefinitionID] = true
		case StatusBlocked, StatusPending:
			state.BlockedSteps[*stepExec.WorkflowStepDefinitionID] = true
		}
	}

	return state, nil
}
