package workflows

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WorkflowStepDefinitionService provides CRUD operations for WorkflowStepDefinition
type WorkflowStepDefinitionService struct {
	db *gorm.DB
}

// NewWorkflowStepDefinitionService creates a new WorkflowStepDefinitionService
func NewWorkflowStepDefinitionService(db *gorm.DB) *WorkflowStepDefinitionService {
	return &WorkflowStepDefinitionService{db: db}
}

// Create creates a new workflow step definition
func (s *WorkflowStepDefinitionService) Create(step *WorkflowStepDefinition) error {
	if step == nil {
		return errors.New("workflow step definition cannot be nil")
	}

	if err := s.ValidateStep(step); err != nil {
		return err
	}

	return s.db.Create(step).Error
}

// GetByID retrieves a workflow step definition by ID
func (s *WorkflowStepDefinitionService) GetByID(id *uuid.UUID) (*WorkflowStepDefinition, error) {
	var step WorkflowStepDefinition
	err := s.db.Preload("DependsOn").
		Preload("DependsOn.DependsOnStep").
		Preload("DependentSteps").
		Preload("Triggers").
		First(&step, id).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("workflow step definition with id %s not found", id.String())
		}
		return nil, err
	}

	return &step, nil
}

// GetByWorkflowDefinitionID retrieves all steps for a workflow definition
func (s *WorkflowStepDefinitionService) GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]WorkflowStepDefinition, error) {
	var steps []WorkflowStepDefinition
	err := s.db.Where("workflow_definition_id = ?", workflowDefID).
		Preload("DependsOn").
		Preload("DependsOn.DependsOnStep").
		Preload("Triggers").
		Find(&steps).Error

	return steps, err
}

// Update updates an existing workflow step definition
func (s *WorkflowStepDefinitionService) Update(id *uuid.UUID, updates *WorkflowStepDefinition) error {
	if updates == nil {
		return errors.New("updates cannot be nil")
	}

	// Check if step exists
	var existing WorkflowStepDefinition
	if err := s.db.First(&existing, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("workflow step definition with id %s not found", id.String())
		}
		return err
	}

	// Validate updates
	if err := s.ValidateStep(updates); err != nil {
		return err
	}

	// Update fields
	updates.ID = id
	return s.db.Model(&existing).Updates(updates).Error
}

// Delete soft deletes a workflow step definition
func (s *WorkflowStepDefinitionService) Delete(id *uuid.UUID) error {
	// Check if step has dependent steps
	var dependentCount int64
	if err := s.db.Model(&StepDependency{}).
		Where("depends_on_step_id = ?", id).
		Count(&dependentCount).Error; err != nil {
		return err
	}

	if dependentCount > 0 {
		return fmt.Errorf("cannot delete step: %d other steps depend on it", dependentCount)
	}

	result := s.db.Delete(&WorkflowStepDefinition{}, id)
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("workflow step definition with id %s not found", id.String())
	}

	return nil
}

// AddDependency adds a dependency between two steps
func (s *WorkflowStepDefinitionService) AddDependency(stepID, dependsOnStepID *uuid.UUID) error {
	// Validate both steps exist
	if _, err := s.GetByID(stepID); err != nil {
		return fmt.Errorf("step not found: %w", err)
	}
	if _, err := s.GetByID(dependsOnStepID); err != nil {
		return fmt.Errorf("depends on step not found: %w", err)
	}

	// Check if dependency already exists
	var existing StepDependency
	err := s.db.Where("workflow_step_definition_id = ? AND depends_on_step_id = ?", stepID, dependsOnStepID).
		First(&existing).Error

	if err == nil {
		return errors.New("dependency already exists")
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// Create dependency
	dependency := &StepDependency{
		WorkflowStepDefinitionID: stepID,
		DependsOnStepID:          dependsOnStepID,
	}

	return s.db.Create(dependency).Error
}

// RemoveDependency removes a dependency between two steps
func (s *WorkflowStepDefinitionService) RemoveDependency(stepID, dependsOnStepID *uuid.UUID) error {
	result := s.db.Where("workflow_step_definition_id = ? AND depends_on_step_id = ?", stepID, dependsOnStepID).
		Delete(&StepDependency{})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return errors.New("dependency not found")
	}

	return nil
}

// GetDependencies retrieves all dependencies for a step
func (s *WorkflowStepDefinitionService) GetDependencies(stepID *uuid.UUID) ([]WorkflowStepDefinition, error) {
	var dependencies []WorkflowStepDefinition
	err := s.db.Joins("JOIN step_dependencies ON step_dependencies.depends_on_step_id = workflow_step_definitions.id").
		Where("step_dependencies.workflow_step_definition_id = ?", stepID).
		Find(&dependencies).Error

	return dependencies, err
}

// GetDependentSteps retrieves all steps that depend on this step
func (s *WorkflowStepDefinitionService) GetDependentSteps(stepID *uuid.UUID) ([]WorkflowStepDefinition, error) {
	var dependents []WorkflowStepDefinition
	err := s.db.Joins("JOIN step_dependencies ON step_dependencies.workflow_step_definition_id = workflow_step_definitions.id").
		Where("step_dependencies.depends_on_step_id = ?", stepID).
		Find(&dependents).Error

	return dependents, err
}

// ValidateStep validates a workflow step definition
func (s *WorkflowStepDefinitionService) ValidateStep(step *WorkflowStepDefinition) error {
	if step == nil {
		return errors.New("workflow step definition cannot be nil")
	}

	if step.Name == "" {
		return errors.New("step name is required")
	}

	if len(step.Name) > 255 {
		return errors.New("step name cannot exceed 255 characters")
	}

	if step.ResponsibleRole == "" {
		return errors.New("responsible role is required")
	}

	if len(step.ResponsibleRole) > 255 {
		return errors.New("responsible role cannot exceed 255 characters")
	}

	if step.WorkflowDefinitionID == nil {
		return errors.New("workflow definition ID is required")
	}

	return nil
}

// HasCircularDependency checks if adding a dependency would create a cycle
func (s *WorkflowStepDefinitionService) HasCircularDependency(stepID, dependsOnStepID *uuid.UUID) (bool, error) {
	// If stepID depends on dependsOnStepID, check if dependsOnStepID (or any of its dependencies)
	// eventually depends on stepID
	visited := make(map[string]bool)
	return s.hasCycleDFS(dependsOnStepID, stepID, visited)
}

// hasCycleDFS performs depth-first search to detect cycles
func (s *WorkflowStepDefinitionService) hasCycleDFS(currentStepID, targetStepID *uuid.UUID, visited map[string]bool) (bool, error) {
	if currentStepID.String() == targetStepID.String() {
		return true, nil
	}

	if visited[currentStepID.String()] {
		return false, nil
	}

	visited[currentStepID.String()] = true

	// Get all dependencies of current step
	dependencies, err := s.GetDependencies(currentStepID)
	if err != nil {
		return false, err
	}

	for _, dep := range dependencies {
		hasCycle, err := s.hasCycleDFS(dep.ID, targetStepID, visited)
		if err != nil {
			return false, err
		}
		if hasCycle {
			return true, nil
		}
	}

	return false, nil
}
