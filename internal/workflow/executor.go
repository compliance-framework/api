package workflow

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
)

// NotificationEnqueuer is the minimal interface for enqueuing workflow notification jobs.
// Implemented by the worker service to avoid a direct River dependency in this package.
type NotificationEnqueuer interface {
	EnqueueWorkflowTaskAssigned(ctx context.Context, stepExecution *workflows.StepExecution) error
	EnqueueWorkflowExecutionFailed(ctx context.Context, execution *workflows.WorkflowExecution) error
}

// DAGExecutor handles the execution of workflow DAGs with dependency resolution
// and parallel step execution capabilities
type DAGExecutor struct {
	stepExecutionService     StepExecutionServiceInterface
	workflowExecutionService WorkflowExecutionServiceInterface
	stepDefinitionService    WorkflowStepDefinitionServiceInterface
	assignmentService        AssignmentServiceInterface
	evidenceIntegration      *EvidenceIntegration // Optional: for evidence stream integration
	notificationEnqueuer     NotificationEnqueuer // Optional: for workflow notification emails
	logger                   *log.Logger
}

// Define interfaces for dependency injection
type StepExecutionServiceInterface interface {
	Create(stepExecution *workflows.StepExecution) error
	GetByID(id *uuid.UUID) (*workflows.StepExecution, error)
	GetByWorkflowExecutionID(executionID *uuid.UUID) ([]workflows.StepExecution, error)
	UpdateStatus(ctx context.Context, id *uuid.UUID, status string) error
	Fail(id *uuid.UUID, reason string) error
	CanUnblock(id *uuid.UUID) (bool, error)
	Unblock(id *uuid.UUID) error
}

type WorkflowExecutionServiceInterface interface {
	Create(execution *workflows.WorkflowExecution) error
	GetByID(id *uuid.UUID) (*workflows.WorkflowExecution, error)
	GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]workflows.WorkflowExecution, error)
	UpdateStatus(ctx context.Context, id *uuid.UUID, status string) error
	Cancel(id *uuid.UUID) error
	Fail(id *uuid.UUID, reason string) error
	FailIfNotTerminal(ctx context.Context, id *uuid.UUID, reason string) (bool, error)
}

type WorkflowStepDefinitionServiceInterface interface {
	GetByID(id *uuid.UUID) (*workflows.WorkflowStepDefinition, error)
	GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
	GetDependencies(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
	GetDependentSteps(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error)
}

type WorkflowInstanceServiceInterface interface {
	GetByID(id *uuid.UUID) (*workflows.WorkflowInstance, error)
	GetDueInstances(ctx context.Context) ([]workflows.WorkflowInstance, error)
	AdvanceSchedule(ctx context.Context, id *uuid.UUID) error
	UpdateSchedule(ctx context.Context, id *uuid.UUID, nextSchedule time.Time) error
}

type AssignmentServiceInterface interface {
	ResolveStepAssignees(ctx context.Context, instance *workflows.WorkflowInstance, stepDefinitions []workflows.WorkflowStepDefinition) (map[uuid.UUID]Assignee, error)
}

// NewDAGExecutor creates a new DAG executor instance
func NewDAGExecutor(
	stepExecutionService StepExecutionServiceInterface,
	workflowExecutionService WorkflowExecutionServiceInterface,
	stepDefinitionService WorkflowStepDefinitionServiceInterface,
	assignmentService AssignmentServiceInterface,
	logger *log.Logger,
	notificationEnqueuer NotificationEnqueuer,
) *DAGExecutor {
	if logger == nil {
		logger = log.Default()
	}

	return &DAGExecutor{
		stepExecutionService:     stepExecutionService,
		workflowExecutionService: workflowExecutionService,
		stepDefinitionService:    stepDefinitionService,
		assignmentService:        assignmentService,
		logger:                   logger,
		notificationEnqueuer:     notificationEnqueuer,
	}
}

// SetEvidenceIntegration sets the evidence integration service (optional)
func (e *DAGExecutor) SetEvidenceIntegration(evidenceIntegration *EvidenceIntegration) {
	e.evidenceIntegration = evidenceIntegration
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
	// Early guard to avoid unnecessary work when initialization is no longer valid.
	// We intentionally re-check this again later (after DB writes) to protect against races.
	if workflowExecution.Status != StatusPending.String() {
		e.logger.Printf("Skipping workflow initialization for execution %s in status %s", workflowExecutionID.String(), workflowExecution.Status)
		return nil
	}

	// Get all step definitions for this workflow
	stepDefinitions, err := e.stepDefinitionService.GetByWorkflowDefinitionID(workflowExecution.WorkflowInstance.WorkflowDefinitionID)
	if err != nil {
		return fmt.Errorf("failed to get step definitions: %w", err)
	}

	if len(stepDefinitions) == 0 {
		return fmt.Errorf("no steps defined for workflow")
	}

	// Resolve step assignments if assignment service is available
	var assignments map[uuid.UUID]Assignee
	if e.assignmentService != nil && workflowExecution.WorkflowInstance != nil {
		var err error
		assignments, err = e.assignmentService.ResolveStepAssignees(ctx, workflowExecution.WorkflowInstance, stepDefinitions)
		if err != nil {
			e.logger.Printf("Warning: failed to resolve step assignees: %v", err)
			// Continue without assignments
		}
	}

	retryCompletedSteps := e.resolveRetryCompletedStepDefinitions(workflowExecution)
	existingStepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get existing step executions: %w", err)
	}
	existingByStepDef := make(map[uuid.UUID]workflows.StepExecution, len(existingStepExecutions))
	for _, existing := range existingStepExecutions {
		if existing.WorkflowStepDefinitionID != nil {
			existingByStepDef[*existing.WorkflowStepDefinitionID] = existing
		}
	}

	// Create step execution records for each step definition
	executionStart := time.Now()
	if workflowExecution.StartedAt != nil {
		executionStart = *workflowExecution.StartedAt
	}

	for _, stepDef := range stepDefinitions {
		if _, exists := existingByStepDef[*stepDef.ID]; exists {
			continue
		}

		// Get dependencies for this step
		dependencies, _ := e.stepDefinitionService.GetDependencies(stepDef.ID)

		// Determine initial status based on dependencies
		initialStatus := StatusPending.String()
		if len(dependencies) > 0 {
			initialStatus = StatusBlocked.String()
		}
		if retryCompletedSteps[*stepDef.ID] {
			initialStatus = StatusCompleted.String()
		}

		stepExecution := &workflows.StepExecution{
			WorkflowExecutionID:      workflowExecutionID,
			WorkflowStepDefinitionID: stepDef.ID,
			Status:                   initialStatus,
		}
		if initialStatus != StatusBlocked.String() {
			graceDays := resolveStepGraceDays(workflowExecution, stepDef)
			dueDate := executionStart.AddDate(0, 0, graceDays)
			stepExecution.DueDate = &dueDate
		}

		// Apply assignment if resolved
		if assignee, ok := assignments[*stepDef.ID]; ok {
			stepExecution.AssignedToType = assignee.Type
			stepExecution.AssignedToID = assignee.ID
			now := time.Now()
			stepExecution.AssignedAt = &now
		}
		if initialStatus == StatusCompleted.String() {
			stepExecution.StartedAt = &executionStart
			stepExecution.CompletedAt = &executionStart
		}

		if err := e.stepExecutionService.Create(stepExecution); err != nil {
			return fmt.Errorf("failed to create step execution for step %s: %w", stepDef.ID.String(), err)
		}

		// Enqueue task-assigned notification for user or email-assigned, actionable steps
		if e.notificationEnqueuer != nil &&
			(stepExecution.AssignedToType == workflows.AssignmentTypeUser.String() ||
				stepExecution.AssignedToType == workflows.AssignmentTypeEmail.String()) &&
			initialStatus == StatusPending.String() {
			if err := e.notificationEnqueuer.EnqueueWorkflowTaskAssigned(ctx, stepExecution); err != nil {
				e.logger.Printf("Warning: failed to enqueue task-assigned notification for step %s: %v", stepDef.ID.String(), err)
			}
		}
	}

	if len(retryCompletedSteps) > 0 {
		if err := e.unblockReadySteps(workflowExecutionID); err != nil {
			e.logger.Printf("Warning: failed to unblock ready steps: %v", err)
		}
	}

	// Re-check status to avoid stale transitions if another worker changed it concurrently.
	workflowExecution, err = e.workflowExecutionService.GetByID(workflowExecutionID)
	if err != nil {
		return fmt.Errorf("failed to reload workflow execution: %w", err)
	}
	if workflowExecution.Status != StatusPending.String() {
		e.logger.Printf("Skipping in_progress transition for execution %s now in status %s", workflowExecutionID.String(), workflowExecution.Status)
		return nil
	}

	// Update workflow execution status to in_progress
	if err := e.workflowExecutionService.UpdateStatus(ctx, workflowExecutionID, StatusInProgress.String()); err != nil {
		return fmt.Errorf("failed to update workflow execution status: %w", err)
	}

	e.logger.Printf("Workflow execution initialized with %d steps", len(stepDefinitions))
	return nil
}

func (e *DAGExecutor) resolveRetryCompletedStepDefinitions(workflowExecution *workflows.WorkflowExecution) map[uuid.UUID]bool {
	completed := make(map[uuid.UUID]bool)
	if workflowExecution == nil || workflowExecution.TriggeredBy != workflows.TriggerManual.String() {
		return completed
	}

	retrySourceID, err := uuid.Parse(workflowExecution.TriggeredByID)
	if err != nil {
		return completed
	}

	sourceExecution, err := e.workflowExecutionService.GetByID(&retrySourceID)
	if err != nil || sourceExecution == nil || sourceExecution.WorkflowInstanceID == nil ||
		workflowExecution.WorkflowInstanceID == nil ||
		*sourceExecution.WorkflowInstanceID != *workflowExecution.WorkflowInstanceID {
		return completed
	}

	sourceSteps, err := e.stepExecutionService.GetByWorkflowExecutionID(sourceExecution.ID)
	if err != nil {
		return completed
	}

	for _, step := range sourceSteps {
		if step.Status == workflows.StepStatusCompleted.String() && step.WorkflowStepDefinitionID != nil {
			completed[*step.WorkflowStepDefinitionID] = true
		}
	}

	return completed
}

func (e *DAGExecutor) unblockReadySteps(workflowExecutionID *uuid.UUID) error {
	stepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		return err
	}
	for i := range stepExecutions {
		_ = e.tryUnblockStep(&stepExecutions[i])
	}
	return nil
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

	// Unblock dependent steps that are now ready
	unblockedCount := e.unblockDependentSteps(stepExecution, dependentSteps)
	e.logger.Printf("Unblocked %d dependent steps", unblockedCount)

	// Check if workflow is complete
	if err := e.checkWorkflowCompletion(ctx, stepExecution.WorkflowExecutionID); err != nil {
		e.logger.Printf("Error checking workflow completion: %v", err)
	}

	// TODO: Hook for automatic evidence check via step triggers

	return nil
}

// ProcessStepFailure propagates a failed step through dependent steps and reevaluates workflow completion.
func (e *DAGExecutor) ProcessStepFailure(ctx context.Context, stepExecutionID *uuid.UUID) error {
	stepExecution, err := e.stepExecutionService.GetByID(stepExecutionID)
	if err != nil {
		return fmt.Errorf("failed to get step execution: %w", err)
	}

	visited := make(map[uuid.UUID]bool)
	var skipDependents func(stepDefID *uuid.UUID) error
	skipDependents = func(stepDefID *uuid.UUID) error {
		dependents, err := e.stepDefinitionService.GetDependentSteps(stepDefID)
		if err != nil {
			return err
		}
		for _, dep := range dependents {
			if dep.ID == nil || visited[*dep.ID] {
				continue
			}
			visited[*dep.ID] = true

			depExec := e.findDependentStepExecution(stepExecution.WorkflowExecutionID, dep.ID)
			if depExec != nil && depExec.Status != StatusCompleted.String() &&
				depExec.Status != StatusFailed.String() &&
				depExec.Status != StatusSkipped.String() &&
				depExec.Status != StatusCancelled.String() {
				if err := e.stepExecutionService.UpdateStatus(ctx, depExec.ID, StatusSkipped.String()); err != nil {
					e.logger.Printf("Failed to skip dependent step %s: %v", depExec.ID.String(), err)
				}
			}

			if err := skipDependents(dep.ID); err != nil {
				return err
			}
		}
		return nil
	}

	if err := skipDependents(stepExecution.WorkflowStepDefinitionID); err != nil {
		return fmt.Errorf("failed to propagate step failure: %w", err)
	}

	return e.checkWorkflowCompletion(ctx, stepExecution.WorkflowExecutionID)
}

// unblockDependentSteps processes dependent steps and unblocks those that are ready
func (e *DAGExecutor) unblockDependentSteps(stepExecution *workflows.StepExecution, dependentSteps []workflows.WorkflowStepDefinition) int {
	unblockedCount := 0

	for _, dependentStepDef := range dependentSteps {
		dependentStepExec := e.findDependentStepExecution(stepExecution.WorkflowExecutionID, dependentStepDef.ID)
		if dependentStepExec == nil {
			continue
		}

		if e.tryUnblockStep(dependentStepExec) {
			unblockedCount++
		}
	}

	return unblockedCount
}

// findDependentStepExecution finds the step execution for a given step definition
func (e *DAGExecutor) findDependentStepExecution(workflowExecutionID, stepDefinitionID *uuid.UUID) *workflows.StepExecution {
	allStepExecutions, err := e.stepExecutionService.GetByWorkflowExecutionID(workflowExecutionID)
	if err != nil {
		e.logger.Printf("Error getting step executions: %v", err)
		return nil
	}

	for i := range allStepExecutions {
		if allStepExecutions[i].WorkflowStepDefinitionID != nil &&
			*allStepExecutions[i].WorkflowStepDefinitionID == *stepDefinitionID {
			return &allStepExecutions[i]
		}
	}

	return nil
}

// tryUnblockStep attempts to unblock a step if it's blocked and all dependencies are satisfied
func (e *DAGExecutor) tryUnblockStep(stepExec *workflows.StepExecution) bool {
	if stepExec.Status != StatusBlocked.String() {
		return false
	}

	canUnblock, err := e.stepExecutionService.CanUnblock(stepExec.ID)
	if err != nil {
		e.logger.Printf("Error checking if step can be unblocked: %v", err)
		return false
	}

	if !canUnblock {
		return false
	}

	if err := e.stepExecutionService.Unblock(stepExec.ID); err != nil {
		e.logger.Printf("Failed to unblock step %s: %v", stepExec.ID.String(), err)
		return false
	}

	e.logger.Printf("Unblocked step: %s", stepExec.ID.String())

	if e.notificationEnqueuer != nil {
		reloaded, err := e.stepExecutionService.GetByID(stepExec.ID)
		if err == nil && reloaded != nil {
			if err := e.notificationEnqueuer.EnqueueWorkflowTaskAssigned(context.Background(), reloaded); err != nil {
				e.logger.Printf("Warning: failed to enqueue task-assigned notification for step %s: %v", stepExec.ID.String(), err)
			}
		}
	}

	return true
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

	counts := CountStepStatuses(stepExecutions)

	// Check if all steps are in terminal states
	if counts.AllTerminal() {
		if counts.Failed > 0 {
			// Workflow failed — use FailIfNotTerminal so that concurrent completions
			// from two step-failure HTTP requests only enqueue the failure email once.
			reason := fmt.Sprintf("%d of %d steps failed", counts.Failed, len(stepExecutions))
			updated, err := e.workflowExecutionService.FailIfNotTerminal(ctx, workflowExecutionID, reason)
			if err != nil {
				return fmt.Errorf("failed to mark workflow as failed: %w", err)
			}
			e.logger.Printf("Workflow execution failed: %s", reason)

			// Only enqueue the notification if this goroutine was the one that performed the update.
			if updated && e.notificationEnqueuer != nil {
				execution, execErr := e.workflowExecutionService.GetByID(workflowExecutionID)
				if execErr == nil {
					if notifyErr := e.notificationEnqueuer.EnqueueWorkflowExecutionFailed(ctx, execution); notifyErr != nil {
						e.logger.Printf("Failed to enqueue workflow-execution-failed notification: %v", notifyErr)
					}
				} else {
					e.logger.Printf("Failed to reload execution for failure notification: %v", execErr)
				}
			}
		} else {
			// All steps reached successful terminal states (completed/skipped)
			if err := e.workflowExecutionService.UpdateStatus(ctx, workflowExecutionID, StatusCompleted.String()); err != nil {
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

func resolveStepGraceDays(workflowExecution *workflows.WorkflowExecution, stepDef workflows.WorkflowStepDefinition) int {
	if stepDef.GracePeriodDays != nil {
		return *stepDef.GracePeriodDays
	}
	// Step due-date initialization uses global workflow defaults from config.
	// Execution failure grace in OverdueService can use an injected default to support worker-level overrides.
	return ResolveGraceDays(workflowExecution.WorkflowInstance, config.DefaultWorkflowConfig().GracePeriodDays)
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
