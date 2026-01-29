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
	GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
	GetDependencies(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
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

// ExecuteWorkflow executes a workflow with DAG evaluation and parallel step execution
func (e *DAGExecutor) ExecuteWorkflow(ctx context.Context, workflowExecutionID *uuid.UUID) (*ExecutionResult, error) {
	e.logger.Printf("Starting workflow execution: %s", workflowExecutionID.String())

	startTime := time.Now()

	// Get workflow execution details
	workflowExecution, err := e.workflowExecutionService.GetByID(workflowExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Get all step definitions for this workflow
	stepDefinitions, err := e.stepDefinitionService.GetByWorkflowDefinitionID(workflowExecution.WorkflowInstance.WorkflowDefinitionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step definitions: %w", err)
	}

	if len(stepDefinitions) == 0 {
		return nil, fmt.Errorf("no steps defined for workflow")
	}

	// Initialize execution state
	executionState := e.initializeExecutionState(workflowExecutionID, stepDefinitions)

	// Update workflow execution status to in_progress
	if err := e.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusInProgress); err != nil {
		return nil, fmt.Errorf("failed to update workflow execution status: %w", err)
	}

	// Execute the workflow
	result, err := e.executeWorkflowSteps(ctx, executionState, stepDefinitions)
	if err != nil {
		e.logger.Printf("Workflow execution failed: %v", err)

		// Update workflow execution status to failed
		if updateErr := e.workflowExecutionService.Fail(workflowExecutionID, err.Error()); updateErr != nil {
			e.logger.Printf("Failed to update workflow execution status: %v", updateErr)
		}

		return result, err
	}

	// Update workflow execution status to completed
	if err := e.workflowExecutionService.UpdateStatus(workflowExecutionID, StatusCompleted); err != nil {
		e.logger.Printf("Failed to update workflow execution status: %v", err)
	}

	// Add execution completion evidence to stream (if evidence integration is enabled)
	if e.evidenceIntegration != nil {
		if err := e.evidenceIntegration.AddExecutionCompletionEvidence(ctx, workflowExecutionID); err != nil {
			e.logger.Printf("Failed to add execution completion evidence: %v", err)
		}
	}

	result.ExecutionTime = time.Since(startTime)
	e.logger.Printf("Workflow execution completed successfully in %v", result.ExecutionTime)

	return result, nil
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

// executeWorkflowSteps executes all steps in the workflow with dependency resolution
func (e *DAGExecutor) executeWorkflowSteps(ctx context.Context, state *ExecutionState, stepDefinitions []workflows.WorkflowStepDefinition) (*ExecutionResult, error) {
	result := &ExecutionResult{
		StepResults: make(map[uuid.UUID]*StepExecutionResult),
		TotalSteps:  len(stepDefinitions),
	}

	executionErrors := make(chan error, len(stepDefinitions))

	// Continue execution until all steps are completed or failed
	for {
		// Find steps that can be executed (dependencies satisfied)
		readySteps := e.getReadySteps(state)

		if len(readySteps) == 0 {
			// Check if execution is complete
			if e.isExecutionComplete(state) {
				break
			}

			// If no ready steps but execution not complete, wait briefly and check again
			// This handles the case where steps are still running
			if len(state.RunningSteps) > 0 {
				e.logger.Printf("Waiting for %d running steps to complete", len(state.RunningSteps))
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
			go func(stepDefID uuid.UUID) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						e.logger.Printf("Step execution panic recovered: %v", r)
						executionErrors <- fmt.Errorf("step %s panicked: %v", stepDefID.String(), r)
						// Mark step as failed in state
						state.mutex.Lock()
						state.FailedSteps[stepDefID] = true
						delete(state.RunningSteps, stepDefID)
						state.mutex.Unlock()
					}
				}()

				if err := e.executeStep(ctx, state, stepDefID, result); err != nil {
					executionErrors <- fmt.Errorf("step %s failed: %w", stepDefID.String(), err)
				}
			}(stepID)
		}

		// Wait for all current batch of steps to complete before finding next ready steps
		wg.Wait()

		// Check for execution errors
		select {
		case err := <-executionErrors:
			e.logger.Printf("Step execution error: %v", err)
			result.Errors = append(result.Errors, err.Error())
		default:
			// No errors
		}
	}

	// Calculate final results
	result.CompletedSteps = len(state.CompletedSteps)
	result.FailedSteps = len(state.FailedSteps)
	result.Success = len(state.FailedSteps) == 0 && len(state.CompletedSteps) == len(stepDefinitions)

	return result, nil
}

// getReadySteps returns steps that are ready to be executed (dependencies satisfied)
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

// executeStep executes a single step and updates the execution state
func (e *DAGExecutor) executeStep(ctx context.Context, state *ExecutionState, stepDefinitionID uuid.UUID, result *ExecutionResult) error {
	stepState := state.StepStates[stepDefinitionID]

	// Mark step as running
	state.mutex.Lock()
	state.RunningSteps[stepDefinitionID] = true
	delete(state.BlockedSteps, stepDefinitionID)
	state.mutex.Unlock()

	// Ensure we always clean up the running state
	defer func() {
		state.mutex.Lock()
		delete(state.RunningSteps, stepDefinitionID)
		state.mutex.Unlock()
	}()

	startTime := time.Now()
	stepState.StartedAt = &startTime
	stepState.Status = StatusInProgress

	e.logger.Printf("Executing step: %s", stepDefinitionID.String())

	// Create step execution record
	stepExecution := &workflows.StepExecution{
		WorkflowExecutionID:      &state.WorkflowExecutionID,
		WorkflowStepDefinitionID: &stepDefinitionID,
		Status:                   StatusInProgress,
		StartedAt:                &startTime,
	}

	if err := e.stepExecutionService.Create(stepExecution); err != nil {
		return fmt.Errorf("failed to create step execution: %w", err)
	}

	// Execute the step (this would be replaced with actual step execution logic)
	// For now, we'll simulate successful execution
	_, err := e.performStepExecution(ctx, stepDefinitionID, *stepExecution.ID)
	if err != nil {
		// Mark step as failed
		completedTime := time.Now()
		stepState.CompletedAt = &completedTime
		stepState.Status = StatusFailed
		stepState.FailureReason = err.Error()

		state.mutex.Lock()
		state.FailedSteps[stepDefinitionID] = true
		state.mutex.Unlock()

		// Update step execution record
		if updateErr := e.stepExecutionService.Fail(stepExecution.ID, err.Error()); updateErr != nil {
			e.logger.Printf("Failed to update step execution status: %v", updateErr)
		}

		result.StepResults[stepDefinitionID] = &StepExecutionResult{
			StepDefinitionID: stepDefinitionID,
			Success:          false,
			Status:           StatusFailed,
			StartedAt:        startTime,
			CompletedAt:      completedTime,
			FailureReason:    err.Error(),
		}

		return err
	}

	// Mark step as completed
	completedTime := time.Now()
	stepState.CompletedAt = &completedTime
	stepState.Status = StatusCompleted

	state.mutex.Lock()
	state.CompletedSteps[stepDefinitionID] = true
	state.mutex.Unlock()

	// Update step execution record
	if err := e.stepExecutionService.UpdateStatus(stepExecution.ID, StatusCompleted); err != nil {
		e.logger.Printf("Failed to update step execution status: %v", err)
	}

	// Add step completion evidence to stream (if evidence integration is enabled)
	if e.evidenceIntegration != nil {
		if err := e.evidenceIntegration.AddStepCompletionEvidence(ctx, stepExecution.ID); err != nil {
			e.logger.Printf("Failed to add step completion evidence: %v", err)
		}
	}

	result.StepResults[stepDefinitionID] = &StepExecutionResult{
		StepDefinitionID: stepDefinitionID,
		Success:          true,
		Status:           StatusCompleted,
		StartedAt:        startTime,
		CompletedAt:      completedTime,
	}

	e.logger.Printf("Step completed successfully: %s", stepDefinitionID.String())

	return nil
}

// performStepExecution performs the actual execution of a step
// This is a placeholder implementation that should be replaced with actual step execution logic
func (e *DAGExecutor) performStepExecution(ctx context.Context, stepDefinitionID, stepExecutionID uuid.UUID) (*StepExecutionResult, error) {
	// Simulate step execution with some work
	select {
	case <-time.After(StepSimulationTime): // Simulate work
		return &StepExecutionResult{
			StepDefinitionID: stepDefinitionID,
			Success:          true,
			Status:           StatusCompleted,
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
		case StatusBlocked, StatusPending:
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
