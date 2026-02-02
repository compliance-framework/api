package workflows

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
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
}

// NewWorkflowExecutionService creates a new WorkflowExecutionService
func NewWorkflowExecutionService(db *gorm.DB) *WorkflowExecutionService {
	return &WorkflowExecutionService{
		db:              db,
		base:            NewBaseService(db),
		evidenceCreator: nil,
	}
}

// SetEvidenceCreator sets the evidence creator for the workflow execution service
func (s *WorkflowExecutionService) SetEvidenceCreator(evidenceCreator WorkflowExecutionEvidenceCreator) {
	s.evidenceCreator = evidenceCreator
}

// Create creates a new workflow execution
func (s *WorkflowExecutionService) Create(execution *WorkflowExecution) error {
	if execution == nil {
		return errors.New("workflow execution cannot be nil")
	}

	if err := s.ValidateExecution(execution); err != nil {
		return err
	}

	// Set default status if not provided
	if execution.Status == "" {
		execution.Status = "pending"
	}

	return s.db.Create(execution).Error
}

// GetByID retrieves a workflow execution by ID
func (s *WorkflowExecutionService) GetByID(id *uuid.UUID) (*WorkflowExecution, error) {
	var execution WorkflowExecution
	err := s.base.GetByIDWithPreload(&execution, id, "workflow execution",
		"WorkflowInstance", "WorkflowInstance.WorkflowDefinition", "WorkflowInstance.WorkflowDefinition.Steps",
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
func (s *WorkflowExecutionService) UpdateStatus(id *uuid.UUID, status string) error {
	if err := ValidateWorkflowExecutionStatus(status); err != nil {
		return err
	}

	updates := map[string]interface{}{"status": status}
	now := time.Now()
	switch status {
	case "in_progress":
		// Add workflow execution started evidence when transitioning to in_progress (while still pending)
		if s.evidenceCreator != nil {
			if err := s.evidenceCreator.AddWorkflowExecutionEvidence(context.Background(), id, "started"); err != nil {
				// Log error but don't fail the status update
				// TODO: Add proper logging
				_ = err // Suppress errcheck warning
			}
		}
		updates["started_at"] = now
	case "completed":
		updates["completed_at"] = now
		if s.evidenceCreator != nil {
			if err := s.evidenceCreator.AddWorkflowExecutionEvidence(context.Background(), id, "completed"); err != nil {
				// Log error but don't fail the status update
				// TODO: Add proper logging
				_ = err // Suppress errcheck warning
			}
		}
	case "failed":
		updates["failed_at"] = now
	}

	return s.base.UpdateStatus(&WorkflowExecution{}, id, status, "status", updates)
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
