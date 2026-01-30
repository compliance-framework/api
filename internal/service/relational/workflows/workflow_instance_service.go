package workflows

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkflowInstanceService provides CRUD operations for WorkflowInstance
type WorkflowInstanceService struct {
	db   *gorm.DB
	base *BaseService
}

// NewWorkflowInstanceService creates a new WorkflowInstanceService
func NewWorkflowInstanceService(db *gorm.DB) *WorkflowInstanceService {
	return &WorkflowInstanceService{
		db:   db,
		base: NewBaseService(db),
	}
}

// Create creates a new workflow instance
func (s *WorkflowInstanceService) Create(instance *WorkflowInstance) error {
	if instance == nil {
		return errors.New("workflow instance cannot be nil")
	}

	if err := s.ValidateInstance(instance); err != nil {
		return err
	}

	// Set next scheduled time if cadence is provided
	if instance.Cadence != "" && instance.NextScheduledAt == nil {
		nextSchedule := s.calculateNextSchedule(time.Now(), instance.Cadence)
		instance.NextScheduledAt = &nextSchedule
	}

	return s.db.Create(instance).Error
}

// GetByID retrieves a workflow instance by ID
func (s *WorkflowInstanceService) GetByID(id *uuid.UUID) (*WorkflowInstance, error) {
	var instance WorkflowInstance
	err := s.base.GetByIDWithPreload(&instance, id, "workflow instance",
		"WorkflowDefinition", "WorkflowDefinition.Steps", "RoleAssignments", "Executions")
	if err != nil {
		return nil, err
	}
	return &instance, nil
}

// GetAll retrieves all workflow instances with optional filters
func (s *WorkflowInstanceService) GetAll(limit, offset int, filters map[string]interface{}) ([]WorkflowInstance, int64, error) {
	var instances []WorkflowInstance
	var total int64

	query := s.db.Model(&WorkflowInstance{})

	// Apply filters
	if workflowDefID, ok := filters["workflow_definition_id"]; ok {
		query = query.Where("workflow_definition_id = ?", workflowDefID)
	}
	if systemSecurityPlanID, ok := filters["system_security_plan_id"]; ok {
		query = query.Where("system_security_plan_id = ?", systemSecurityPlanID)
	}
	if isActive, ok := filters["is_active"]; ok {
		query = query.Where("is_active = ?", isActive)
	}

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.Preload("WorkflowDefinition").
		Preload("RoleAssignments").
		Limit(limit).
		Offset(offset).
		Find(&instances).Error

	if err != nil {
		return nil, 0, err
	}

	return instances, total, nil
}

// GetByWorkflowDefinitionID retrieves all instances for a workflow definition
func (s *WorkflowInstanceService) GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]WorkflowInstance, error) {
	var instances []WorkflowInstance
	err := s.db.Where("workflow_definition_id = ?", workflowDefID).
		Preload("RoleAssignments").
		Preload("Executions").
		Find(&instances).Error

	return instances, err
}

// Update updates an existing workflow instance
func (s *WorkflowInstanceService) Update(id *uuid.UUID, updates *WorkflowInstance) error {
	if err := s.base.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	if err := s.ValidateInstance(updates); err != nil {
		return err
	}

	var existing WorkflowInstance
	updates.ID = id
	return s.base.UpdateEntity(&existing, updates, id, "workflow instance")
}

// Delete soft deletes a workflow instance
func (s *WorkflowInstanceService) Delete(id *uuid.UUID) error {
	return s.base.DeleteEntity(&WorkflowInstance{}, id, "workflow instance")
}

// Activate activates a workflow instance
func (s *WorkflowInstanceService) Activate(id *uuid.UUID) error {
	return s.base.ActivateEntity(&WorkflowInstance{}, id)
}

// Deactivate deactivates a workflow instance
func (s *WorkflowInstanceService) Deactivate(id *uuid.UUID) error {
	return s.base.DeactivateEntity(&WorkflowInstance{}, id)
}

// UpdateSchedule updates the next scheduled time for an instance
func (s *WorkflowInstanceService) UpdateSchedule(id *uuid.UUID, nextSchedule time.Time) error {
	return s.db.Model(&WorkflowInstance{}).
		Where("id = ?", id).
		Update("next_scheduled_at", nextSchedule).Error
}

// UpdateLastExecuted updates the last executed time for an instance
func (s *WorkflowInstanceService) UpdateLastExecuted(id *uuid.UUID, lastExecuted time.Time) error {
	return s.db.Model(&WorkflowInstance{}).
		Where("id = ?", id).
		Update("last_executed_at", lastExecuted).Error
}

// GetDueInstances retrieves all instances that are due for execution
func (s *WorkflowInstanceService) GetDueInstances() ([]WorkflowInstance, error) {
	var instances []WorkflowInstance
	now := time.Now()

	err := s.db.Where("is_active = ? AND next_scheduled_at <= ?", true, now).
		Preload("WorkflowDefinition").
		Preload("WorkflowDefinition.Steps").
		Preload("RoleAssignments").
		Find(&instances).Error

	return instances, err
}

// ValidateInstance validates a workflow instance
func (s *WorkflowInstanceService) ValidateInstance(instance *WorkflowInstance) error {
	if instance == nil {
		return errors.New("workflow instance cannot be nil")
	}

	return CombineErrors(
		ValidateStringRequired(instance.Name, "instance name"),
		ValidateStringLength(instance.Name, "instance name", MaxNameLength),
		ValidateUUIDRequired(instance.SystemSecurityPlanID, "system security plan ID"),
		ValidateUUIDRequired(instance.WorkflowDefinitionID, "workflow definition ID"),
		ValidateCadence(instance.Cadence),
	)
}

// calculateNextSchedule calculates the next scheduled time based on cadence
func (s *WorkflowInstanceService) calculateNextSchedule(from time.Time, cadence string) time.Time {
	switch cadence {
	case "daily":
		return from.AddDate(0, 0, 1)
	case "weekly":
		return from.AddDate(0, 0, 7)
	case "monthly":
		return from.AddDate(0, 1, 0)
	case "quarterly":
		return from.AddDate(0, 3, 0)
	case "annually":
		return from.AddDate(1, 0, 0)
	default:
		return from.AddDate(0, 1, 0) // Default to monthly
	}
}

// GetBySystemId retrieves all instances for a specific system
func (s *WorkflowInstanceService) GetBySystemId(systemId *uuid.UUID) ([]WorkflowInstance, error) {
	var instances []WorkflowInstance
	err := s.db.Where("system_security_plan_id = ?", systemId).
		Preload("WorkflowDefinition").
		Preload("RoleAssignments").
		Find(&instances).Error

	return instances, err
}
