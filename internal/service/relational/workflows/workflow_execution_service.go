package workflows

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// WorkflowExecutionEvidenceCreator interface for creating workflow execution evidence
type WorkflowExecutionEvidenceCreator interface {
	AddWorkflowExecutionEvidence(ctx context.Context, workflowExecutionID *uuid.UUID, status string) error
}

// WorkflowExecutionService provides CRUD operations for WorkflowExecution
type WorkflowExecutionService struct {
	db              *gorm.DB
	base            *BaseService
	evidenceCreator WorkflowExecutionEvidenceCreator
	logger          *zap.SugaredLogger
}

var ErrInvalidWorkflowExecutionStatusTransition = errors.New("invalid workflow execution status transition")
var ErrWorkflowExecutionStatusTransitionConflict = errors.New("workflow execution status transition conflict")

// NewWorkflowExecutionService creates a new WorkflowExecutionService
func NewWorkflowExecutionService(db *gorm.DB) *WorkflowExecutionService {
	return &WorkflowExecutionService{
		db:              db,
		base:            NewBaseService(db),
		evidenceCreator: nil,
		logger:          zap.NewNop().Sugar(), // Default no-op logger
	}
}

// SetLogger sets the logger for the service
func (s *WorkflowExecutionService) SetLogger(logger *zap.SugaredLogger) {
	s.logger = logger
}

// SetEvidenceCreator sets the evidence creator for the workflow execution service
func (s *WorkflowExecutionService) SetEvidenceCreator(evidenceCreator WorkflowExecutionEvidenceCreator) {
	s.evidenceCreator = evidenceCreator
}

// Create creates a new workflow execution
func (s *WorkflowExecutionService) Create(execution *WorkflowExecution) error {
	return s.base.ValidateAndCreate(execution, "workflow execution", func() error {
		return s.ValidateExecution(execution)
	})
}

// GetByID retrieves a workflow execution by ID
func (s *WorkflowExecutionService) GetByID(id *uuid.UUID) (*WorkflowExecution, error) {
	var execution WorkflowExecution
	err := s.base.GetByIDWithPreload(&execution, id, "workflow execution",
		"WorkflowInstance", "WorkflowInstance.WorkflowDefinition", "WorkflowInstance.WorkflowDefinition.Steps",
		"WorkflowInstance.RoleAssignments",
		"StepExecutions", "StepExecutions.WorkflowStepDefinition", "StepExecutions.StepEvidence")
	if err != nil {
		return nil, err
	}
	return &execution, nil
}

// GetByWorkflowInstanceID retrieves all executions for a workflow instance
func (s *WorkflowExecutionService) GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]WorkflowExecution, error) {
	var executions []WorkflowExecution
	err := s.db.Where("workflow_instance_id = ?", instanceID).
		Preload("StepExecutions").
		Order("created_at DESC").
		Find(&executions).Error

	return executions, err
}

// GetAll retrieves all workflow executions with optional filters
func (s *WorkflowExecutionService) GetAll(limit, offset int, filters map[string]interface{}) ([]WorkflowExecution, int64, error) {
	var executions []WorkflowExecution
	var total int64

	query := s.db.Model(&WorkflowExecution{})

	// Apply filters
	if instanceID, ok := filters["workflow_instance_id"]; ok {
		query = query.Where("workflow_instance_id = ?", instanceID)
	}
	if status, ok := filters["status"]; ok {
		query = query.Where("status = ?", status)
	}
	if triggeredBy, ok := filters["triggered_by"]; ok {
		query = query.Where("triggered_by = ?", triggeredBy)
	}

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.Preload("WorkflowInstance").
		Preload("StepExecutions").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&executions).Error

	if err != nil {
		return nil, 0, err
	}

	return executions, total, nil
}

// Update updates an existing workflow execution
func (s *WorkflowExecutionService) Update(id *uuid.UUID, updates *WorkflowExecution) error {
	if err := s.base.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	var existing WorkflowExecution
	// Don't modify the updates object, just pass it to UpdateEntity
	return s.base.UpdateEntity(&existing, updates, id, "workflow execution")
}

// UpdateStatus updates the status of a workflow execution
func (s *WorkflowExecutionService) UpdateStatus(ctx context.Context, id *uuid.UUID, status string) error {
	if err := ValidateWorkflowExecutionStatus(status); err != nil {
		return err
	}

	var current WorkflowExecution
	if err := s.db.WithContext(ctx).Select("status").First(&current, "id = ?", id).Error; err != nil {
		return err
	}
	if current.Status == status {
		return nil
	}
	if !isValidExecutionStatusTransition(current.Status, status) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidWorkflowExecutionStatusTransition, current.Status, status)
	}

	updates := map[string]interface{}{"status": status}
	now := time.Now()
	switch status {
	case "in_progress":
		updates["started_at"] = now
	case "completed":
		updates["completed_at"] = now
	case "overdue":
		updates["overdue_at"] = now
	case "failed":
		updates["failed_at"] = now
	}

	result := s.db.WithContext(ctx).
		Model(&WorkflowExecution{}).
		Where("id = ? AND status = ?", id, current.Status).
		Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		var latest WorkflowExecution
		if err := s.db.WithContext(ctx).Select("status").First(&latest, "id = ?", id).Error; err != nil {
			return err
		}
		if latest.Status == status {
			return nil
		}
		if !isValidExecutionStatusTransition(latest.Status, status) {
			return fmt.Errorf("%w: %s -> %s", ErrInvalidWorkflowExecutionStatusTransition, latest.Status, status)
		}
		return fmt.Errorf("%w: %s -> %s", ErrWorkflowExecutionStatusTransitionConflict, current.Status, status)
	}

	if s.evidenceCreator != nil {
		switch status {
		case "in_progress":
			if err := s.evidenceCreator.AddWorkflowExecutionEvidence(ctx, id, "started"); err != nil {
				s.logger.Warnw("Failed to create workflow execution started evidence",
					"workflow_execution_id", id,
					"error", err)
			}
		case "completed":
			if err := s.evidenceCreator.AddWorkflowExecutionEvidence(ctx, id, "completed"); err != nil {
				s.logger.Warnw("Failed to create workflow execution completed evidence",
					"workflow_execution_id", id,
					"error", err)
			}
		}
	}

	return nil
}

func isValidExecutionStatusTransition(current, next string) bool {
	switch current {
	case WorkflowStatusPending.String():
		return next == WorkflowStatusPending.String() ||
			next == WorkflowStatusInProgress.String() ||
			next == WorkflowStatusOverdue.String() ||
			next == WorkflowStatusCancelled.String() ||
			next == WorkflowStatusFailed.String()
	case WorkflowStatusInProgress.String():
		return next == WorkflowStatusInProgress.String() ||
			next == WorkflowStatusCompleted.String() ||
			next == WorkflowStatusFailed.String() ||
			next == WorkflowStatusOverdue.String() ||
			next == WorkflowStatusCancelled.String()
	case WorkflowStatusOverdue.String():
		return next == WorkflowStatusOverdue.String() ||
			next == WorkflowStatusFailed.String() ||
			next == WorkflowStatusCompleted.String() ||
			next == WorkflowStatusCancelled.String()
	case WorkflowStatusCompleted.String(), WorkflowStatusFailed.String(), WorkflowStatusCancelled.String():
		return next == current || (current == WorkflowStatusCompleted.String() && next == WorkflowStatusFailed.String())
	default:
		return false
	}
}

// Start marks a workflow execution as started
func (s *WorkflowExecutionService) Start(id *uuid.UUID) error {
	now := time.Now()
	return s.base.UpdateStatus(&WorkflowExecution{}, id, "in_progress", "status", map[string]interface{}{
		"status":     "in_progress",
		"started_at": now,
	})
}

// Complete marks a workflow execution as completed
func (s *WorkflowExecutionService) Complete(id *uuid.UUID) error {
	now := time.Now()
	return s.base.UpdateStatus(&WorkflowExecution{}, id, "completed", "status", map[string]interface{}{
		"status":       "completed",
		"completed_at": now,
	})
}

// Fail marks a workflow execution as failed
func (s *WorkflowExecutionService) Fail(id *uuid.UUID, reason string) error {
	now := time.Now()
	return s.base.UpdateStatus(&WorkflowExecution{}, id, "failed", "status", map[string]interface{}{
		"status":         "failed",
		"failed_at":      now,
		"failure_reason": reason,
	})
}

// Cancel cancels a workflow execution
func (s *WorkflowExecutionService) Cancel(id *uuid.UUID) error {
	return s.db.Model(&WorkflowExecution{}).
		Where("id = ?", id).
		Update("status", "cancelled").Error
}

// GetActiveExecutions retrieves all active (in_progress) executions
func (s *WorkflowExecutionService) GetActiveExecutions() ([]WorkflowExecution, error) {
	var executions []WorkflowExecution
	err := s.db.Where("status = ?", "in_progress").
		Preload("WorkflowInstance").
		Preload("StepExecutions").
		Find(&executions).Error

	return executions, err
}

// GetRecentExecutions retrieves recent executions within a time range
func (s *WorkflowExecutionService) GetRecentExecutions(since time.Time, limit int) ([]WorkflowExecution, error) {
	var executions []WorkflowExecution
	err := s.db.Where("created_at >= ?", since).
		Preload("WorkflowInstance").
		Order("created_at DESC").
		Limit(limit).
		Find(&executions).Error

	return executions, err
}

// ValidateExecution validates a workflow execution
func (s *WorkflowExecutionService) ValidateExecution(execution *WorkflowExecution) error {
	if execution == nil {
		return errors.New("workflow execution cannot be nil")
	}

	return CombineErrors(
		ValidateUUIDRequired(execution.WorkflowInstanceID, "workflow instance ID"),
		ValidateTriggerType(execution.TriggeredBy),
	)
}

// GetExecutionProgress calculates the progress of a workflow execution
func (s *WorkflowExecutionService) GetExecutionProgress(id *uuid.UUID) (completed, total int, err error) {
	var stepExecutions []StepExecution
	err = s.db.Where("workflow_execution_id = ?", id).Find(&stepExecutions).Error
	if err != nil {
		return 0, 0, err
	}

	total = len(stepExecutions)
	for _, step := range stepExecutions {
		if step.Status == "completed" {
			completed++
		}
	}

	return completed, total, nil
}
