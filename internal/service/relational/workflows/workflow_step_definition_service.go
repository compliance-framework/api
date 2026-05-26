package workflows

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// WorkflowStepDefinitionService provides CRUD operations for WorkflowStepDefinition
type WorkflowStepDefinitionService struct {
	db   *gorm.DB
	base *BaseService
}

// NewWorkflowStepDefinitionService creates a new WorkflowStepDefinitionService
func NewWorkflowStepDefinitionService(db *gorm.DB) *WorkflowStepDefinitionService {
	return &WorkflowStepDefinitionService{
		db:   db,
		base: NewBaseService(db),
	}
}

// Create creates a new workflow step definition
func (s *WorkflowStepDefinitionService) Create(step *WorkflowStepDefinition) error {
	// When a grace period is provided, lock the definition row so that concurrent
	// creates against the same definition cannot both pass the sibling-sum check and
	// collectively exceed the definition's grace period limit.
	if step != nil && step.GracePeriodDays != nil && step.WorkflowDefinitionID != nil {
		return s.db.Transaction(func(tx *gorm.DB) error {
			if err := s.lockDefinition(tx, step.WorkflowDefinitionID); err != nil {
				return err
			}
			return s.base.ValidateAndCreate(step, "workflow step definition", func() error {
				return s.validateStep(tx, step, nil)
			})
		})
	}
	return s.base.ValidateAndCreate(step, "workflow step definition", func() error {
		return s.ValidateStep(step)
	})
}

// lockDefinition acquires a write lock on a workflow definition row to serialize
// concurrent grace-period writes. On PostgreSQL this issues SELECT … FOR UPDATE;
// on other databases (e.g. SQLite in tests) the clause is skipped and the transaction
// alone provides the available isolation.
func (s *WorkflowStepDefinitionService) lockDefinition(db *gorm.DB, id *uuid.UUID) error {
	q := db.Model(&WorkflowDefinition{}).Select("id").Where("id = ?", id)
	if db.Name() == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := q.First(&WorkflowDefinition{}).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("workflow definition with id %s not found", id.String())
		}
		return fmt.Errorf("failed to lock workflow definition: %w", err)
	}
	return nil
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

// GetByWorkflowDefinitionID retrieves all steps for a workflow definition ordered by the order field
func (s *WorkflowStepDefinitionService) GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]WorkflowStepDefinition, error) {
	var steps []WorkflowStepDefinition
	err := s.db.Where("workflow_definition_id = ?", workflowDefID).
		Order("\"order\" ASC").
		Preload("DependsOn").
		Preload("DependsOn.DependsOnStep").
		Preload("Triggers").
		Find(&steps).Error

	return steps, err
}

// Update updates an existing workflow step definition
func (s *WorkflowStepDefinitionService) Update(id *uuid.UUID, updates *WorkflowStepDefinition) error {
	var existing WorkflowStepDefinition
	// When grace period is being updated, lock the definition row to serialize concurrent
	// updates so that the sibling-sum check cannot be defeated by concurrent writes.
	if updates != nil && updates.GracePeriodDays != nil && updates.WorkflowDefinitionID != nil {
		return s.db.Transaction(func(tx *gorm.DB) error {
			if err := s.lockDefinition(tx, updates.WorkflowDefinitionID); err != nil {
				return err
			}
			return s.base.ValidateAndUpdate(&existing, updates, id, "workflow step definition", func() error {
				updates.ID = id
				return s.validateStep(tx, updates, updates.ID)
			})
		})
	}
	return s.base.ValidateAndUpdate(&existing, updates, id, "workflow step definition", func() error {
		updates.ID = id
		return s.ValidateStepUpdate(updates)
	})
}

// Delete soft deletes a workflow step definition
func (s *WorkflowStepDefinitionService) Delete(id *uuid.UUID) error {
	// Check if step has active dependent steps
	var dependentCount int64
	if err := s.db.Model(&StepDependency{}).
		Joins("JOIN workflow_step_definitions ON workflow_step_definitions.id = step_dependencies.workflow_step_definition_id").
		Where("step_dependencies.depends_on_step_id = ? AND workflow_step_definitions.deleted_at IS NULL", id).
		Count(&dependentCount).Error; err != nil {
		return err
	}

	if dependentCount > 0 {
		return validationErrorf("cannot delete step: %d other steps depend on it", dependentCount)
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
		return validationError("dependency already exists")
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

// GetDependentSteps retrieves all steps that depend on this step ordered by the order field
func (s *WorkflowStepDefinitionService) GetDependentSteps(stepID *uuid.UUID) ([]WorkflowStepDefinition, error) {
	var dependents []WorkflowStepDefinition
	err := s.db.Joins("JOIN step_dependencies ON step_dependencies.workflow_step_definition_id = workflow_step_definitions.id").
		Where("step_dependencies.depends_on_step_id = ?", stepID).
		Order("workflow_step_definitions.\"order\" ASC").
		Find(&dependents).Error

	return dependents, err
}

// ValidateStep validates a workflow step definition for creation.
func (s *WorkflowStepDefinitionService) ValidateStep(step *WorkflowStepDefinition) error {
	return s.validateStep(s.db, step, nil)
}

// ValidateStepUpdate validates a workflow step definition for an update, excluding
// the step's own current grace period from the sibling sum. The update path receives
// a fully populated step (the handler merges request fields onto the loaded row), so
// the same invariants as creation are enforced.
func (s *WorkflowStepDefinitionService) ValidateStepUpdate(step *WorkflowStepDefinition) error {
	return s.validateStep(s.db, step, step.ID)
}

// validateStep is the shared validation logic for create and update.
// db is the connection (or transaction) to use for grace-period DB lookups.
// excludeID, when non-nil, is excluded from the sibling grace period sum (update path).
func (s *WorkflowStepDefinitionService) validateStep(db *gorm.DB, step *WorkflowStepDefinition, excludeID *uuid.UUID) error {
	if step == nil {
		return validationError("workflow step definition cannot be nil")
	}

	if step.Name == "" {
		return validationError("step name is required")
	}

	if len(step.Name) > 255 {
		return validationError("step name cannot exceed 255 characters")
	}

	if step.ResponsibleRole == "" {
		return validationError("responsible role is required")
	}

	if len(step.ResponsibleRole) > 255 {
		return validationError("responsible role cannot exceed 255 characters")
	}

	if step.WorkflowDefinitionID == nil {
		return validationError("workflow definition ID is required")
	}
	if step.GracePeriodDays != nil && *step.GracePeriodDays < 0 {
		return validationError("grace period days must be non-negative")
	}

	// BCH-1152: sum of step grace periods must not exceed the definition grace period.
	if step.GracePeriodDays != nil {
		var defGrace *int
		if err := db.Model(&WorkflowDefinition{}).
			Select("grace_period_days").
			Where("id = ?", step.WorkflowDefinitionID).
			Scan(&defGrace).Error; err != nil {
			return fmt.Errorf("failed to look up workflow definition grace period: %w", err)
		}
		if defGrace != nil {
			var siblingSum int
			q := db.Model(&WorkflowStepDefinition{}).
				Select("COALESCE(SUM(grace_period_days), 0)").
				Where("workflow_definition_id = ? AND grace_period_days IS NOT NULL AND deleted_at IS NULL", step.WorkflowDefinitionID)
			if excludeID != nil {
				q = q.Where("id != ?", excludeID)
			}
			if err := q.Scan(&siblingSum).Error; err != nil {
				return fmt.Errorf("failed to calculate sibling grace period sum: %w", err)
			}
			if siblingSum+*step.GracePeriodDays > *defGrace {
				return validationErrorf("step grace period days would cause the total step grace period (%d) to exceed the workflow definition grace period (%d)", siblingSum+*step.GracePeriodDays, *defGrace)
			}
		}
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
