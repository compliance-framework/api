package workflows

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// StepEvidenceCreator interface to avoid import cycle
type StepEvidenceCreator interface {
	AddStepStartedEvidence(ctx context.Context, stepExecutionID *uuid.UUID) error
}

// StepExecutionService provides CRUD operations for StepExecution
type StepExecutionService struct {
	db              *gorm.DB
	base            *BaseService
	evidenceCreator StepEvidenceCreator
}

// NewStepExecutionService creates a new StepExecutionService
func NewStepExecutionService(db *gorm.DB, evidenceCreator StepEvidenceCreator) *StepExecutionService {
	return &StepExecutionService{
		db:              db,
		base:            NewBaseService(db),
		evidenceCreator: evidenceCreator,
	}
}

// SetEvidenceCreator sets the evidence creator (to avoid circular dependency)
func (s *StepExecutionService) SetEvidenceCreator(creator StepEvidenceCreator) {
	s.evidenceCreator = creator
}

// Create creates a new step execution
func (s *StepExecutionService) Create(stepExecution *StepExecution) error {
	if stepExecution == nil {
		return errors.New("step execution cannot be nil")
	}

	if err := ValidateStepExecution(stepExecution); err != nil {
		return err
	}

	// Set default status if not provided
	if stepExecution.Status == "" {
		stepExecution.Status = "pending"
	}

	err := s.db.Create(stepExecution).Error
	if err != nil {
		return err
	}

	// Note: Step started evidence is only added when transitioning from pending -> in_progress
	// not when creating the step with pending status

	return nil
}

// GetByID retrieves a step execution by ID
func (s *StepExecutionService) GetByID(id *uuid.UUID) (*StepExecution, error) {
	var stepExecution StepExecution
	err := s.base.GetByIDWithPreload(&stepExecution, id, "step execution",
		"WorkflowExecution", "WorkflowStepDefinition", "StepEvidence")
	if err != nil {
		return nil, err
	}
	return &stepExecution, nil
}

// GetByWorkflowExecutionID retrieves all step executions for a workflow execution ordered by step definition order
func (s *StepExecutionService) GetByWorkflowExecutionID(executionID *uuid.UUID) ([]StepExecution, error) {
	var stepExecutions []StepExecution
	err := s.db.Joins("JOIN workflow_step_definitions ON workflow_step_definitions.id = step_executions.workflow_step_definition_id").
		Where("step_executions.workflow_execution_id = ?", executionID).
		Order("workflow_step_definitions.\"order\" ASC").
		Preload("WorkflowStepDefinition").
		Preload("StepEvidence").
		Find(&stepExecutions).Error

	return stepExecutions, err
}

// Update updates an existing step execution
func (s *StepExecutionService) Update(id *uuid.UUID, updates *StepExecution) error {
	if updates == nil {
		return errors.New("updates cannot be nil")
	}
	if err := s.base.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	var existing StepExecution
	updates.ID = id
	return s.base.UpdateEntity(&existing, updates, id, "step execution")
}

// UpdateStatus updates the status of a step execution
func (s *StepExecutionService) UpdateStatus(id *uuid.UUID, status string) error {
	if err := ValidateStepExecutionStatus(status); err != nil {
		return err
	}

	updates := map[string]interface{}{"status": status}
	now := time.Now()
	switch status {
	case "in_progress":
		updates["started_at"] = now
		// Add step started evidence when transitioning to in_progress
		if s.evidenceCreator != nil {
			if err := s.evidenceCreator.AddStepStartedEvidence(context.Background(), id); err != nil {
				// Log error but don't fail the status update
				// TODO: Add proper logging
				_ = err // Suppress errcheck warning
			}
		}
	case "completed":
		updates["completed_at"] = now
	case "failed":
		updates["failed_at"] = now
	}

	return s.base.UpdateStatus(&StepExecution{}, id, status, "status", updates)
}

// Start marks a step execution as started
func (s *StepExecutionService) Start(id *uuid.UUID) error {
	now := time.Now()
	err := s.base.UpdateStatus(&StepExecution{}, id, "in_progress", "status", map[string]interface{}{
		"status":     "in_progress",
		"started_at": now,
	})
	if err != nil {
		return err
	}

	// Add step started evidence for in_progress steps
	if s.evidenceCreator != nil {
		if err := s.evidenceCreator.AddStepStartedEvidence(context.Background(), id); err != nil {
			// Log error but don't fail the start
			// TODO: Add proper logging
			_ = err // Suppress errcheck warning
		}
	}

	return nil
}

// Complete marks a step execution as completed
func (s *StepExecutionService) Complete(id *uuid.UUID) error {
	now := time.Now()
	return s.base.UpdateStatus(&StepExecution{}, id, "completed", "status", map[string]interface{}{
		"status":       "completed",
		"completed_at": now,
	})
}

// Fail marks a step execution as failed
func (s *StepExecutionService) Fail(id *uuid.UUID, reason string) error {
	now := time.Now()
	return s.base.UpdateStatus(&StepExecution{}, id, "failed", "status", map[string]interface{}{
		"status":         "failed",
		"failed_at":      now,
		"failure_reason": reason,
	})
}

// Block marks a step execution as blocked
func (s *StepExecutionService) Block(id *uuid.UUID) error {
	return s.db.Model(&StepExecution{}).
		Where("id = ?", id).
		Update("status", "blocked").Error
}

// Unblock marks a step execution as unblocked (pending)
func (s *StepExecutionService) Unblock(id *uuid.UUID) error {
	return s.db.Model(&StepExecution{}).
		Where("id = ?", id).
		Update("status", "pending").Error
}

// AssignTo assigns a step execution to a user or group
func (s *StepExecutionService) AssignTo(id *uuid.UUID, assignedToType, assignedToID string) error {
	now := time.Now()
	return s.db.Model(&StepExecution{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"assigned_to_type": assignedToType,
			"assigned_to_id":   assignedToID,
			"assigned_at":      now,
		}).Error
}

// GetPendingSteps retrieves all pending step executions for a workflow execution
func (s *StepExecutionService) GetPendingSteps(executionID *uuid.UUID) ([]StepExecution, error) {
	var stepExecutions []StepExecution
	err := s.db.Where("workflow_execution_id = ? AND status = ?", executionID, "pending").
		Preload("WorkflowStepDefinition").
		Find(&stepExecutions).Error

	return stepExecutions, err
}

// GetBlockedSteps retrieves all blocked step executions for a workflow execution
func (s *StepExecutionService) GetBlockedSteps(executionID *uuid.UUID) ([]StepExecution, error) {
	var stepExecutions []StepExecution
	err := s.db.Where("workflow_execution_id = ? AND status = ?", executionID, "blocked").
		Preload("WorkflowStepDefinition").
		Find(&stepExecutions).Error

	return stepExecutions, err
}

// GetCompletedSteps retrieves all completed step executions for a workflow execution
func (s *StepExecutionService) GetCompletedSteps(executionID *uuid.UUID) ([]StepExecution, error) {
	var stepExecutions []StepExecution
	err := s.db.Where("workflow_execution_id = ? AND status = ?", executionID, "completed").
		Preload("WorkflowStepDefinition").
		Find(&stepExecutions).Error

	return stepExecutions, err
}

// GetAssignedSteps retrieves all step executions assigned to a specific user/group
func (s *StepExecutionService) GetAssignedSteps(assignedToType, assignedToID string) ([]StepExecution, error) {
	var stepExecutions []StepExecution
	err := s.db.Where("assigned_to_type = ? AND assigned_to_id = ? AND status IN ?",
		assignedToType, assignedToID, []string{"pending", "in_progress", "blocked"}).
		Preload("WorkflowExecution").
		Preload("WorkflowExecution.WorkflowInstance").
		Preload("WorkflowStepDefinition").
		Order("created_at ASC").
		Find(&stepExecutions).Error

	return stepExecutions, err
}

// ValidateStepExecution validates a step execution
func ValidateStepExecution(stepExecution *StepExecution) error {
	if err := ValidateNotNil(stepExecution, "step execution"); err != nil {
		return err
	}

	var errs []error
	if err := ValidateUUIDRequired(stepExecution.WorkflowExecutionID, "workflow execution ID"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateUUIDRequired(stepExecution.WorkflowStepDefinitionID, "workflow step definition ID"); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return CombineErrors(errs...)
	}

	return nil
}

// CanUnblock checks if a step execution can be unblocked based on its dependencies
func (s *StepExecutionService) CanUnblock(id *uuid.UUID) (bool, error) {
	stepExec, err := s.GetByID(id)
	if err != nil {
		return false, err
	}

	// Get the step definition to check dependencies
	var stepDef WorkflowStepDefinition
	if err := s.db.Preload("DependsOn").First(&stepDef, stepExec.WorkflowStepDefinitionID).Error; err != nil {
		return false, err
	}

	// If no dependencies, can unblock
	if len(stepDef.DependsOn) == 0 {
		return true, nil
	}

	// Check if all dependency steps are completed
	for _, dep := range stepDef.DependsOn {
		var depStepExec StepExecution
		err := s.db.Where("workflow_execution_id = ? AND workflow_step_definition_id = ?",
			stepExec.WorkflowExecutionID, dep.DependsOnStepID).
			First(&depStepExec).Error

		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return false, nil // Dependency step not found
			}
			return false, err
		}

		if depStepExec.Status != "completed" {
			return false, nil // Dependency not completed
		}
	}

	return true, nil
}

// GetUnblockableSteps retrieves all step executions that can be unblocked
func (s *StepExecutionService) GetUnblockableSteps(executionID *uuid.UUID) ([]StepExecution, error) {
	blockedSteps, err := s.GetBlockedSteps(executionID)
	if err != nil {
		return nil, err
	}

	var unblockable []StepExecution
	for _, step := range blockedSteps {
		canUnblock, err := s.CanUnblock(step.ID)
		if err != nil {
			return nil, err
		}
		if canUnblock {
			unblockable = append(unblockable, step)
		}
	}

	return unblockable, nil
}
