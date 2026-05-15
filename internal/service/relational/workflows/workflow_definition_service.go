package workflows

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkflowDefinitionService provides CRUD operations for WorkflowDefinition
type WorkflowDefinitionService struct {
	db   *gorm.DB
	base *BaseService
}

// NewWorkflowDefinitionService creates a new WorkflowDefinitionService
func NewWorkflowDefinitionService(db *gorm.DB) *WorkflowDefinitionService {
	return &WorkflowDefinitionService{
		db:   db,
		base: NewBaseService(db),
	}
}

// Create creates a new workflow definition
func (s *WorkflowDefinitionService) Create(definition *WorkflowDefinition) error {
	return s.base.ValidateAndCreate(definition, "workflow definition", func() error {
		return s.ValidateDefinition(definition)
	})
}

// GetByID retrieves a workflow definition by ID
func (s *WorkflowDefinitionService) GetByID(id *uuid.UUID) (*WorkflowDefinition, error) {
	var definition WorkflowDefinition
	err := s.base.GetByIDWithPreload(&definition, id, "workflow definition",
		"Steps", "Steps.DependsOn", "Steps.Triggers", "ControlRelationships")
	if err != nil {
		return nil, err
	}
	return &definition, nil
}

// GetAll retrieves all workflow definitions with optional filters
func (s *WorkflowDefinitionService) GetAll(limit, offset int) ([]WorkflowDefinition, int64, error) {
	var definitions []WorkflowDefinition
	var total int64

	// Count total records
	if err := s.db.Model(&WorkflowDefinition{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := s.db.Preload("Steps").
		Preload("ControlRelationships").
		Limit(limit).
		Offset(offset).
		Find(&definitions).Error

	if err != nil {
		return nil, 0, err
	}

	return definitions, total, nil
}

// Update updates an existing workflow definition
func (s *WorkflowDefinitionService) Update(id *uuid.UUID, updates *WorkflowDefinition) error {
	if err := s.base.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	if err := s.ValidateDefinition(updates); err != nil {
		return err
	}

	var existing WorkflowDefinition
	// Don't modify the updates object, just pass it to UpdateEntity
	return s.base.UpdateEntity(&existing, updates, id, "workflow definition")
}

// Delete soft deletes a workflow definition
func (s *WorkflowDefinitionService) Delete(id *uuid.UUID) error {
	return s.base.DeleteEntity(&WorkflowDefinition{}, id, "workflow definition")
}

// FindByName finds workflow definitions by name (partial match)
func (s *WorkflowDefinitionService) FindByName(name string) ([]WorkflowDefinition, error) {
	var definitions []WorkflowDefinition
	err := s.db.Where("name LIKE ?", "%"+name+"%").
		Preload("Steps").
		Preload("ControlRelationships").
		Find(&definitions).Error

	return definitions, err
}

// GetWithInstances retrieves a workflow definition with all its instances
func (s *WorkflowDefinitionService) GetWithInstances(id *uuid.UUID) (*WorkflowDefinition, error) {
	var definition WorkflowDefinition
	err := s.base.GetByIDWithPreload(&definition, id, "workflow definition",
		"Steps", "Steps.DependsOn", "ControlRelationships", "Instances", "Instances.RoleAssignments")
	if err != nil {
		return nil, err
	}
	return &definition, nil
}

// ValidateDefinition validates a workflow definition before creation/update
func (s *WorkflowDefinitionService) ValidateDefinition(definition *WorkflowDefinition) error {
	if definition == nil {
		return errors.New("workflow definition cannot be nil")
	}
	if definition.GracePeriodDays != nil && *definition.GracePeriodDays < 0 {
		return errors.New("grace period days must be non-negative")
	}
	if err := s.validateGracePeriodHierarchy(definition); err != nil {
		return err
	}

	return CombineErrors(
		ValidateStringRequired(definition.Name, "workflow definition name"),
		ValidateStringLength(definition.Name, "workflow definition name", MaxNameLength),
		ValidateCadence(definition.SuggestedCadence),
	)
}

func (s *WorkflowDefinitionService) validateGracePeriodHierarchy(definition *WorkflowDefinition) error {
	if definition.ID == nil || definition.GracePeriodDays == nil {
		return nil
	}

	var instanceCount int64
	if err := s.db.Model(&WorkflowInstance{}).
		Where("workflow_definition_id = ? AND grace_period_days IS NOT NULL AND grace_period_days > ?", definition.ID, *definition.GracePeriodDays).
		Count(&instanceCount).Error; err != nil {
		return err
	}
	if instanceCount > 0 {
		return fmt.Errorf("workflow definition grace period days must be greater than or equal to explicit workflow instance grace period days")
	}

	var stepCount int64
	if err := s.db.Model(&WorkflowStepDefinition{}).
		Where("workflow_definition_id = ? AND grace_period_days IS NOT NULL AND grace_period_days > ?", definition.ID, *definition.GracePeriodDays).
		Count(&stepCount).Error; err != nil {
		return err
	}
	if stepCount > 0 {
		return fmt.Errorf("workflow definition grace period days must be greater than or equal to explicit workflow step grace period days")
	}

	return nil
}

// CountInstances counts the number of instances for a workflow definition
func (s *WorkflowDefinitionService) CountInstances(id *uuid.UUID) (int64, error) {
	return s.base.CountWhere(&WorkflowInstance{}, "workflow_definition_id = ?", id)
}
