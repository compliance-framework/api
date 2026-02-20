package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
)

var ErrWorkflowExecutionAlreadyExists = errors.New("workflow execution already exists for instance and period")

// Manager orchestrates workflow execution lifecycle using River for async operations
type Manager struct {
	riverClient              RiverClient
	workflowExecutionService WorkflowExecutionServiceInterface
	workflowInstanceService  WorkflowInstanceServiceInterface
	stepExecutionService     StepExecutionServiceInterface
	notificationEnqueuer     NotificationEnqueuer // Optional: for workflow notification emails
	logger                   *zap.SugaredLogger
}

// SetNotificationEnqueuer sets the notification enqueuer (optional)
func (m *Manager) SetNotificationEnqueuer(enqueuer NotificationEnqueuer) {
	m.notificationEnqueuer = enqueuer
}

// NewManager creates a new workflow manager
func NewManager(
	riverClient RiverClient,
	workflowExecutionService WorkflowExecutionServiceInterface,
	workflowInstanceService WorkflowInstanceServiceInterface,
	stepExecutionService StepExecutionServiceInterface,
	logger *zap.SugaredLogger,
) *Manager {
	return &Manager{
		riverClient:              riverClient,
		workflowExecutionService: workflowExecutionService,
		workflowInstanceService:  workflowInstanceService,
		stepExecutionService:     stepExecutionService,
		logger:                   logger,
	}
}

// NewManagerWithRiver creates a manager with a River client and concrete services
func NewManagerWithRiver(
	riverClient *river.Client[pgx.Tx],
	workflowExecutionService *workflows.WorkflowExecutionService,
	workflowInstanceService *workflows.WorkflowInstanceService,
	stepExecutionService *workflows.StepExecutionService,
	logger *zap.SugaredLogger,
) *Manager {
	return NewManager(
		riverClient,
		workflowExecutionService,
		workflowInstanceService,
		stepExecutionService,
		logger,
	)
}

// StartWorkflowOptions contains options for starting a workflow execution
type StartWorkflowOptions struct {
	TriggeredBy   string
	TriggeredByID string
	PeriodLabel   string
	DueDate       *time.Time
}

// StartWorkflowExecution creates and starts a workflow execution via River
func (m *Manager) StartWorkflowExecution(ctx context.Context, workflowInstanceID *uuid.UUID, opts StartWorkflowOptions) (*uuid.UUID, error) {
	m.logger.Infow("Starting workflow execution",
		"workflow_instance_id", workflowInstanceID,
		"triggered_by", opts.TriggeredBy,
		"triggered_by_id", opts.TriggeredByID,
		"period_label", opts.PeriodLabel,
	)

	// Get workflow instance
	instance, err := m.workflowInstanceService.GetByID(workflowInstanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow instance: %w", err)
	}

	// Check if instance is active
	if !instance.IsActive {
		return nil, fmt.Errorf("cannot start execution for inactive workflow instance")
	}

	// Create workflow execution record
	now := time.Now()
	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: workflowInstanceID,
		Status:             "pending",
		TriggeredBy:        opts.TriggeredBy,
		TriggeredByID:      opts.TriggeredByID,
		StartedAt:          &now,
		PeriodLabel:        opts.PeriodLabel,
		DueDate:            opts.DueDate,
	}

	if err := m.workflowExecutionService.Create(execution); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && opts.TriggeredBy == workflows.TriggerScheduled.String() {
			return nil, fmt.Errorf("%w", ErrWorkflowExecutionAlreadyExists)
		}
		return nil, fmt.Errorf("failed to create workflow execution: %w", err)
	}

	m.logger.Infow("Workflow execution created",
		"execution_id", execution.ID,
		"workflow_instance_id", workflowInstanceID,
	)

	// Enqueue workflow execution job via River
	args := &ExecuteWorkflowArgs{
		WorkflowExecutionID: *execution.ID,
		TriggeredBy:         opts.TriggeredBy,
		TriggeredByID:       opts.TriggeredByID,
	}

	_, err = m.riverClient.InsertMany(ctx, []river.InsertManyParams{
		{Args: args, InsertOpts: JobInsertOptionsForWorkflow()},
	})
	if err != nil {
		// Mark execution as failed
		if failErr := m.workflowExecutionService.Fail(execution.ID, fmt.Sprintf("Failed to enqueue job: %v", err)); failErr != nil {
			m.logger.Errorw("Failed to mark execution as failed", "error", failErr)
		} else if m.notificationEnqueuer != nil {
			if reloaded, reloadErr := m.workflowExecutionService.GetByID(execution.ID); reloadErr == nil {
				if notifyErr := m.notificationEnqueuer.EnqueueWorkflowExecutionFailed(ctx, reloaded); notifyErr != nil {
					m.logger.Errorw("Failed to enqueue workflow-execution-failed notification", "error", notifyErr)
				}
			}
		}
		return nil, fmt.Errorf("failed to enqueue workflow execution job: %w", err)
	}

	m.logger.Infow("Workflow execution job enqueued",
		"execution_id", execution.ID,
		"job_kind", JobTypeExecuteWorkflow,
	)

	return execution.ID, nil
}

// GetExecutionStatus returns the current status of a workflow execution
func (m *Manager) GetExecutionStatus(ctx context.Context, executionID *uuid.UUID) (*ExecutionStatus, error) {
	// Get workflow execution
	execution, err := m.workflowExecutionService.GetByID(executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Get step executions
	stepExecutions, err := m.stepExecutionService.GetByWorkflowExecutionID(executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step executions: %w", err)
	}

	// Count steps by status
	var pending, blocked, inProgress, overdue, completed, failed, cancelled int
	for _, step := range stepExecutions {
		switch step.Status {
		case "pending":
			pending++
		case "blocked":
			blocked++
		case "in_progress":
			inProgress++
		case "overdue":
			overdue++
		case "completed":
			completed++
		case "failed":
			failed++
		case "cancelled":
			cancelled++
		}
	}

	status := &ExecutionStatus{
		ExecutionID:     *executionID,
		Status:          execution.Status,
		TotalSteps:      len(stepExecutions),
		PendingSteps:    pending,
		BlockedSteps:    blocked,
		InProgressSteps: inProgress,
		OverdueSteps:    overdue,
		CompletedSteps:  completed,
		FailedSteps:     failed,
		CancelledSteps:  cancelled,
		StartedAt:       execution.StartedAt,
		CompletedAt:     execution.CompletedAt,
		FailedAt:        execution.FailedAt,
		FailureReason:   execution.FailureReason,
	}

	return status, nil
}

// CancelExecution cancels a running workflow execution
func (m *Manager) CancelExecution(ctx context.Context, executionID *uuid.UUID, reason string) error {
	m.logger.Infow("Cancelling workflow execution",
		"execution_id", executionID,
		"reason", reason,
	)

	// Get workflow execution
	execution, err := m.workflowExecutionService.GetByID(executionID)
	if err != nil {
		return fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Check if execution can be cancelled
	if execution.Status == "completed" || execution.Status == "failed" || execution.Status == "cancelled" {
		return fmt.Errorf("cannot cancel execution in status: %s", execution.Status)
	}

	// Update execution status
	if err := m.workflowExecutionService.Cancel(executionID); err != nil {
		return fmt.Errorf("failed to cancel workflow execution: %w", err)
	}

	// Cancel all in-progress and pending steps
	stepExecutions, err := m.stepExecutionService.GetByWorkflowExecutionID(executionID)
	if err != nil {
		return fmt.Errorf("failed to get step executions: %w", err)
	}

	for _, step := range stepExecutions {
		if step.Status == "in_progress" || step.Status == "pending" || step.Status == "blocked" {
			// Update step status to cancelled
			if err := m.stepExecutionService.UpdateStatus(ctx, step.ID, "cancelled"); err != nil {
				m.logger.Warnw("Failed to cancel step execution",
					"step_execution_id", step.ID,
					"error", err,
				)
			}
		}
	}

	m.logger.Infow("Workflow execution cancelled",
		"execution_id", executionID,
	)

	return nil
}

// RetryExecution creates a new execution for a failed workflow
func (m *Manager) RetryExecution(ctx context.Context, executionID *uuid.UUID) (*uuid.UUID, error) {
	m.logger.Infow("Retrying workflow execution",
		"original_execution_id", executionID,
	)

	// Get original execution
	execution, err := m.workflowExecutionService.GetByID(executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	// Check if execution can be retried
	if execution.Status != "failed" && execution.Status != "cancelled" {
		return nil, fmt.Errorf("can only retry failed or cancelled executions, current status: %s", execution.Status)
	}

	// Start new execution (use "manual" as trigger type, with original execution ID as triggered_by_id)
	// For retries, we intentionally do NOT carry over the original PeriodLabel, so that the retry is
	// treated as a distinct, ad-hoc run and cannot be confused with the original scheduled execution
	// for that period.
	opts := StartWorkflowOptions{
		TriggeredBy:   workflows.TriggerManual.String(),
		TriggeredByID: executionID.String(),
	}

	newExecutionID, err := m.StartWorkflowExecution(
		ctx,
		execution.WorkflowInstanceID,
		opts,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start retry execution: %w", err)
	}

	m.logger.Infow("Workflow execution retry started",
		"original_execution_id", executionID,
		"new_execution_id", newExecutionID,
	)

	return newExecutionID, nil
}

// ListExecutions returns workflow executions for a workflow instance
func (m *Manager) ListExecutions(ctx context.Context, workflowInstanceID *uuid.UUID, limit, offset int) ([]*workflows.WorkflowExecution, error) {
	executions, err := m.workflowExecutionService.GetByWorkflowInstanceID(workflowInstanceID)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflow executions: %w", err)
	}

	// Apply pagination
	start := offset
	if start > len(executions) {
		return []*workflows.WorkflowExecution{}, nil
	}

	end := start + limit
	if end > len(executions) {
		end = len(executions)
	}

	// Convert slice to pointer slice
	result := make([]*workflows.WorkflowExecution, end-start)
	for i := start; i < end; i++ {
		result[i-start] = &executions[i]
	}

	return result, nil
}

// GetExecutionMetrics returns metrics for a workflow execution
func (m *Manager) GetExecutionMetrics(ctx context.Context, executionID *uuid.UUID) (*ExecutionMetrics, error) {
	execution, err := m.workflowExecutionService.GetByID(executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get workflow execution: %w", err)
	}

	stepExecutions, err := m.stepExecutionService.GetByWorkflowExecutionID(executionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get step executions: %w", err)
	}

	metrics := &ExecutionMetrics{
		ExecutionID: *executionID,
		TotalSteps:  len(stepExecutions),
	}

	// Calculate execution duration
	if execution.StartedAt != nil {
		if execution.CompletedAt != nil {
			metrics.Duration = execution.CompletedAt.Sub(*execution.StartedAt)
		} else if execution.FailedAt != nil {
			metrics.Duration = execution.FailedAt.Sub(*execution.StartedAt)
		} else {
			metrics.Duration = time.Since(*execution.StartedAt)
		}
	}

	// Calculate step metrics
	var totalStepDuration time.Duration
	for _, step := range stepExecutions {
		if step.StartedAt != nil && step.CompletedAt != nil {
			stepDuration := step.CompletedAt.Sub(*step.StartedAt)
			totalStepDuration += stepDuration

			if stepDuration > metrics.LongestStepDuration {
				metrics.LongestStepDuration = stepDuration
			}
		}
	}

	if len(stepExecutions) > 0 {
		metrics.AverageStepDuration = totalStepDuration / time.Duration(len(stepExecutions))
	}

	return metrics, nil
}

// ExecutionStatus represents the current status of a workflow execution
type ExecutionStatus struct {
	ExecutionID     uuid.UUID
	Status          string
	TotalSteps      int
	PendingSteps    int
	BlockedSteps    int
	InProgressSteps int
	OverdueSteps    int
	CompletedSteps  int
	FailedSteps     int
	CancelledSteps  int
	StartedAt       *time.Time
	CompletedAt     *time.Time
	FailedAt        *time.Time
	FailureReason   string
}

// ExecutionMetrics represents metrics for a workflow execution
type ExecutionMetrics struct {
	ExecutionID         uuid.UUID
	TotalSteps          int
	Duration            time.Duration
	AverageStepDuration time.Duration
	LongestStepDuration time.Duration
}
