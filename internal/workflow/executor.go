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

// DAGExecutor handles the execution of workflow DAGs with dependency resolution
// and parallel step execution capabilities
type DAGExecutor struct {
	stepExecutionService     StepExecutionServiceInterface
	workflowExecutionService WorkflowExecutionServiceInterface
	stepDefinitionService    WorkflowStepDefinitionServiceInterface
	evidenceIntegration      *EvidenceIntegration // Optional: for evidence stream integration
	logger                   *log.Logger
}

// Define interfaces for dependency injection
type StepExecutionServiceInterface interface {
	Create(stepExecution *workflows.StepExecution) error
	GetByID(id *uuid.UUID) (*workflows.StepExecution, error)
	GetByWorkflowExecutionID(executionID *uuid.UUID) ([]workflows.StepExecution, error)
	UpdateStatus(id *uuid.UUID, status string) error
	Fail(id *uuid.UUID, reason string) error
	CanUnblock(id *uuid.UUID) (bool, error)
	Unblock(id *uuid.UUID) error
}

type WorkflowExecutionServiceInterface interface {
	Create(execution *workflows.WorkflowExecution) error
	GetByID(id *uuid.UUID) (*workflows.WorkflowExecution, error)
	GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]workflows.WorkflowExecution, error)
	UpdateStatus(id *uuid.UUID, status string) error
	Cancel(id *uuid.UUID) error
	Fail(id *uuid.UUID, reason string) error
}

type WorkflowStepDefinitionServiceInterface interface {
	GetByID(id *uuid.UUID) (*workflows.WorkflowStepDefinition, error)
	GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
	GetDependencies(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
	GetDependentSteps(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
}

type WorkflowInstanceServiceInterface interface {
	GetByID(id *uuid.UUID) (*workflows.WorkflowInstance, error)
}

// NewDAGExecutor creates a new DAG executor instance
func NewDAGExecutor(
	stepExecutionService StepExecutionServiceInterface,
	workflowExecutionService WorkflowExecutionServiceInterface,
	stepDefinitionService WorkflowStepDefinitionServiceInterface,
	logger *log.Logger,
) *DAGExecutor {
	if logger == nil {
		logger = log.Default()
	}

	return &DAGExecutor{
		stepExecutionService:     stepExecutionService,
		workflowExecutionService: workflowExecutionService,
		stepDefinitionService:    stepDefinitionService,
		logger:                   logger,
	}
}

// SetEvidenceIntegration sets the evidence integration service (optional)
func (e *DAGExecutor) SetEvidenceIntegration(evidenceIntegration *EvidenceIntegration) {
	e.evidenceIntegration = evidenceIntegration
}

// ExecutionState tracks the current state of a workflow execution
type ExecutionState struct {
	WorkflowExecutionID uuid.UUID
	StepStates          map[uuid.UUID]*StepState
	CompletedSteps      map[uuid.UUID]bool
	FailedSteps         map[uuid.UUID]bool
	RunningSteps        map[uuid.UUID]bool
	BlockedSteps        map[uuid.UUID]bool
	mutex               sync.RWMutex
}

// StepState represents the execution state of an individual step
type StepState struct {
	StepDefinitionID uuid.UUID
	Status           string
	StartedAt        *time.Time
	CompletedAt      *time.Time
	FailureReason    string
	Dependencies     []uuid.UUID
	Dependents       []uuid.UUID
}

// ExecutionResult contains the results of a workflow execution
type ExecutionResult struct {
	Success        bool
	CompletedSteps int
	FailedSteps    int
	TotalSteps     int
	ExecutionTime  time.Duration
	Errors         []string
	StepResults    map[uuid.UUID]*StepExecutionResult
}

// StepExecutionResult contains the result of an individual step execution
type StepExecutionResult struct {
	StepDefinitionID uuid.UUID
	Success          bool
	Status           string
	StartedAt        time.Time
	CompletedAt      time.Time
	FailureReason    string
}

// InitializeWorkflow initializes a workflow execution by creating step execution records
// and setting up the initial DAG state (blocked/pending based on dependencies)
func (e *DAGExecutor) InitializeWorkflow(ctx context.Context, workflowExecutionID *uuid.UUID) error {
	e.logger.Printf("Initializing workflow execution: %s", workflowExecutionID.String())

	// Get workflow execution details
	workflowExecution, err := e.workflowExecutionService.GetByID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Get all step definitions for this workflow
	stepDefinitions, err := e.stepDefinitionService.GetByWorkflowDefinitionID(workflowExecution.WorkflowInstance.WorkflowDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get step definitions: %w", err)
	}

	if len(stepDefinitions) == 0 {
		return fmt.Errorf("no steps defined for workflow")
	}

	// Create step execution records for each step definition
	for _, stepDef := range stepDefinitions {
		// Get dependencies for this step
		dependencies, _ := e.stepDefinitionService.GetDependencies(stepDef.ID)

		// Determine initial status based on dependencies
		initialStatus := StatusPending
		if len(dependencies) > 0 {
			initialStatus = StatusBlocked
		}

		stepExecution := &workflows.StepExecution{
			WorkflowExecutionID:      workflowExecutionID,
			WorkflowStepDefinitionID: stepDef.ID,
			Status:                   initialStatus,
		}

		if err := e.stepExecutionService.Create(stepExecution); err != nil {
			return fmt.Errorf("failed to create step execution for step %s: %w", stepDef.ID.String(), err)
		}
	}

	// Update workflow execution status to in_progress
	if err := e.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusInProgress); err != nil {
		return fmt.Errorf("failed to update workflow execution status: %w", err)
	}

	e.logger.Printf("Workflow execution initialized with %d steps", len(stepDefinitions))
	return nil
}

// initializeExecutionState creates and initializes the execution state for a workflow
func (e *DAGExecutor) initializeExecutionState(workflowExecutionID *uuid.UUID, stepDefinitions []workflows.WorkflowStepDefinition) *ExecutionState {
	state := &ExecutionState{
		WorkflowExecutionID: *workflowExecutionID,
		StepStates:          make(map[uuid.UUID]*StepState),
		CompletedSteps:      make(map[uuid.UUID]bool),
		FailedSteps:         make(map[uuid.UUID]bool),
		RunningSteps:        make(map[uuid.UUID]bool),
		BlockedSteps:        make(map[uuid.UUID]bool),
	}

	// Initialize step states
	for _, stepDef := range stepDefinitions {
		// Get dependencies for this step
		dependencies, _ := e.stepDefinitionService.GetDependencies(stepDef.ID)

		// Convert dependencies to UUID slice
		depIDs := make([]uuid.UUID, len(dependencies))
		for i, dep := range dependencies {
			depIDs[i] = *dep.ID
		}

		stepState := &StepState{
			StepDefinitionID: *stepDef.ID,
			Status:           StatusPending,
			Dependencies:     depIDs,
		}

		state.StepStates[*stepDef.ID] = stepState

		// Initially block steps that have dependencies
		if len(depIDs) > 0 {
			state.BlockedSteps[*stepDef.ID] = true
		}
	}

	return state
}

// ProcessStepCompletion processes a step completion and unblocks dependent steps
// This is called after a user manually completes a step
func (e *DAGExecutor) ProcessStepCompletion(ctx context.Context, stepExecutionID *uuid.UUID) error {
	e.logger.Printf("Processing step completion: %s", stepExecutionID.String())

	// Get the step execution
	stepExecution, err := e.stepExecutionService.GetByID(stepExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	// Get only the direct dependent steps of the completed step
	dependentSteps, err := e.stepDefinitionService.GetDependentSteps(stepExecution.WorkflowStepDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get dependent steps: %w", err)
	}

	// Find and unblock dependent steps that are now ready
	unblockedCount := 0
	for _, dependentStepDef := range dependentSteps {
		// Find the step execution for this dependent step
		allStepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(stepExecution.WorkflowExecutionID)
		if err != nil {
			e.logger.Printf("Error getting step executions: %v", err)
			continue
		}

		// Find the execution for this dependent step definition
		var dependentStepExec *workflows.StepExecution
		for i := range allStepExecutions {
			if allStepExecutions[i].WorkflowStepDefinitionID != nil &&
				*allStepExecutions[i].WorkflowStepDefinitionID == *dependentStepDef.ID {
				dependentStepExec = &allStepExecutions[i]
				break
			}
		}

		if dependentStepExec == nil || dependentStepExec.Status != StatusBlocked {
			continue
		}

		// Check if this dependent step can now be unblocked
		canUnblock, err := e.stepExecutionService.CanUnblock(dependentStepExec.ID)
		if err != nil {
			e.logger.Printf("Error checking if step can be unblocked: %v", err)
			continue
		}

		if canUnblock {
			if err := e.stepExecutionService.Unblock(dependentStepExec.ID); err != nil {
				e.logger.Printf("Failed to unblock step %s: %v", dependentStepExec.ID.String(), err)
			} else {
				e.logger.Printf("Unblocked step: %s", dependentStepExec.ID.String())
				unblockedCount++
				// TODO: Hook for notification - step is now ready for user action
			}
		}
	}

	e.logger.Printf("Unblocked %d dependent steps", unblockedCount)

	// Check if workflow is complete
	if err := e.checkWorkflowCompletion(ctx, stepExecution.WorkflowExecutionID); err != nil {
		e.logger.Printf("Error checking workflow completion: %v", err)
	}

	// TODO: Hook for automatic evidence check via step triggers

	return nil
}

// getReadySteps returns steps that are ready to be executed (dependencies satisfied)
// NOTE: This method uses in-memory ExecutionState and is NOT used in the runtime execution path.
// Runtime execution uses database-backed CanUnblock() in ProcessStepCompletion.
// This method is kept for testing and benchmarking purposes only.
func (e *DAGExecutor) getReadySteps(state *ExecutionState) []uuid.UUID {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	var readySteps []uuid.UUID

	for stepID, stepState := range state.StepStates {
		// Skip steps that are already completed, failed, or running
		if state.CompletedSteps[stepID] || state.FailedSteps[stepID] || state.RunningSteps[stepID] {
			continue
		}

		// Check if all dependencies are completed
		if e.areDependenciesCompleted(state, stepState.Dependencies) {
			readySteps = append(readySteps, stepID)
		}
	}

	return readySteps
}

// areDependenciesCompleted checks if all dependencies for a step are completed
func (e *DAGExecutor) areDependenciesCompleted(state *ExecutionState, dependencies []uuid.UUID) bool {
	for _, depID := range dependencies {
		if !state.CompletedSteps[depID] {
			return false
		}
	}
	return true
}

// isExecutionComplete checks if all steps are completed or failed
func (e *DAGExecutor) isExecutionComplete(state *ExecutionState) bool {
	state.mutex.RLock()
	defer state.mutex.RUnlock()

	totalSteps := len(state.StepStates)
	completedOrFailed := len(state.CompletedSteps) + len(state.FailedSteps)

	return completedOrFailed >= totalSteps
}

// checkWorkflowCompletion checks if all steps are complete and updates workflow status
func (e *DAGExecutor) checkWorkflowCompletion(ctx context.Context, workflowExecutionID *uuid.UUID) error {
	// Get all step executions
	stepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step executions: %w", err)
	}

	if len(stepExecutions) == 0 {
		return nil
	}

	completedCount := 0
	failedCount := 0
	for _, stepExec := range stepExecutions {
		switch stepExec.Status {
		case StatusCompleted:
			completedCount++
		case StatusFailed:
			failedCount++
		}
	}

	// Check if all steps are completed or failed
	if completedCount+failedCount == len(stepExecutions) {
		if failedCount > 0 {
			// Workflow failed
			reason := fmt.Sprintf("%d of %d steps failed", failedCount, len(stepExecutions))
			if err := e.workflowExecutionService.Fail(workflowExecutionID, reason); err != nil {
				return fmt.Errorf("failed to mark workflow as failed: %w", err)
			}
			e.logger.Printf("Workflow execution failed: %s", reason)
		} else {
			// All steps completed successfully
			if err := e.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusCompleted); err != nil {
				return fmt.Errorf("failed to mark workflow as completed: %w", err)
			}

			// Add execution completion evidence to stream (if evidence integration is enabled)
			if e.evidenceIntegration != nil {
				if err := e.evidenceIntegration.AddExecutionCompletionEvidence(ctx, workflowExecutionID); err != nil {
					e.logger.Printf("Failed to add execution completion evidence: %v", err)
				}
			}

			e.logger.Printf("Workflow execution completed successfully")
		}
	}

	return nil
}

// CheckAutomaticTriggers checks if a step has automatic triggers configured
// and evaluates them (for future Phase 5 implementation)
func (e *DAGExecutor) CheckAutomaticTriggers(ctx context.Context, stepExecutionID *uuid.UUID) error {
	// TODO: Phase 5 - Implement automatic step transition triggers
	// This will check StepTrigger configurations and evaluate conditions
	// For now, this is just a placeholder hook
	e.logger.Printf("Checking automatic triggers for step: %s (not yet implemented)", stepExecutionID.String())
	return nil
}

// GetExecutionStatus returns the current status of a workflow execution
func (e *DAGExecutor) GetExecutionStatus(workflowExecutionID *uuid.UUID) (*ExecutionState, error) {
	// Get all step executions for this workflow
	stepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
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
		case StatusBlocked:
			state.BlockedSteps[*stepExec.WorkflowStepDefinitionID] = true
		}
	}

	return state, nil
}

// CancelExecution cancels a running workflow execution
func (e *DAGExecutor) CancelExecution(ctx context.Context, workflowExecutionID *uuid.UUID) error {
	e.logger.Printf("Cancelling workflow execution: %s", workflowExecutionID.String())

	// Update workflow execution status to cancelled
	if err := e.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusCancelled); err != nil {
		return fmt.Errorf("failed to update workflow execution status: %w", err)
	}

	// Cancel all running step executions
	stepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step executions: %w", err)
	}

	for _, stepExec := range stepExecutions {
		if stepExec.Status == StatusInProgress {
			if err := e.stepExecutionService.UpdateStatus(stepExec.ID, StatusCancelled); err != nil {
				e.logger.Printf("Failed to cancel step execution %s: %v", stepExec.ID.String(), err)
			}
		}
	}

	e.logger.Printf("Workflow execution cancelled: %s", workflowExecutionID.String())
	return nil
}
