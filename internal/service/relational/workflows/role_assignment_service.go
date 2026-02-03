package workflows

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RoleAssignmentService provides CRUD operations for RoleAssignment
type RoleAssignmentService struct {
	db   *gorm.DB
	base *BaseService
}

// NewRoleAssignmentService creates a new RoleAssignmentService
func NewRoleAssignmentService(db *gorm.DB) *RoleAssignmentService {
	return &RoleAssignmentService{
		db:   db,
		base: NewBaseService(db),
	}
}

// Create creates a new role assignment
func (s *RoleAssignmentService) Create(assignment *RoleAssignment) error {
	return s.base.ValidateAndCreate(assignment, "role assignment", func() error {
		return s.ValidateAssignment(assignment)
	})
}

// GetByID retrieves a role assignment by ID
func (s *RoleAssignmentService) GetByID(id *uuid.UUID) (*RoleAssignment, error) {
	var assignment RoleAssignment
	err := s.base.GetByIDWithPreload(&assignment, id, "role assignment", "WorkflowInstance")
	if err != nil {
		return nil, err
	}
	return &assignment, nil
}

// GetByWorkflowInstanceID retrieves all role assignments for a workflow instance
func (s *RoleAssignmentService) GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]RoleAssignment, error) {
	var assignments []RoleAssignment
	err := s.db.Where("workflow_instance_id = ?", instanceID).
		Find(&assignments).Error

	return assignments, err
}

// GetByRole retrieves all role assignments for a specific role
func (s *RoleAssignmentService) GetByRole(instanceID *uuid.UUID, roleName string) ([]RoleAssignment, error) {
	var assignments []RoleAssignment
	err := s.db.Where("workflow_instance_id = ? AND role_name = ?", instanceID, roleName).
		Find(&assignments).Error

	return assignments, err
}

// GetByAssignee retrieves all role assignments for a specific assignee
func (s *RoleAssignmentService) GetByAssignee(assignedToType, assignedToID string) ([]RoleAssignment, error) {
	var assignments []RoleAssignment
	err := s.db.Where("assigned_to_type = ? AND assigned_to_id = ? AND is_active = ?",
		assignedToType, assignedToID, true).
		Preload("WorkflowInstance").
		Find(&assignments).Error

	return assignments, err
}

// Update updates an existing role assignment
func (s *RoleAssignmentService) Update(id *uuid.UUID, updates *RoleAssignment) error {
	var existing RoleAssignment
	return s.base.ValidateAndUpdate(&existing, updates, id, "role assignment", nil)
}

// Delete deletes a role assignment
func (s *RoleAssignmentService) Delete(id *uuid.UUID) error {
	return s.base.DeleteEntity(&RoleAssignment{}, id, "role assignment")
}

// Activate activates a role assignment
func (s *RoleAssignmentService) Activate(id *uuid.UUID) error {
	return s.base.ActivateEntity(&RoleAssignment{}, id)
}

// Deactivate deactivates a role assignment
func (s *RoleAssignmentService) Deactivate(id *uuid.UUID) error {
	return s.base.DeactivateEntity(&RoleAssignment{}, id)
}

// ReassignRole reassigns a role to a different assignee
func (s *RoleAssignmentService) ReassignRole(id *uuid.UUID, newAssignedToType, newAssignedToID string) error {
	if err := ValidateStringRequired(newAssignedToType, "assigned to type"); err != nil {
		return err
	}
	if err := ValidateStringRequired(newAssignedToID, "assigned to ID"); err != nil {
		return err
	}
	if err := ValidateAssignmentType(newAssignedToType); err != nil {
		return err
	}

	return s.db.Model(&RoleAssignment{}).Where("id = ?", id).Updates(map[string]interface{}{
		"assigned_to_type": newAssignedToType,
		"assigned_to_id":   newAssignedToID,
	}).Error
}

// ValidateAssignment validates a role assignment
func (s *RoleAssignmentService) ValidateAssignment(assignment *RoleAssignment) error {
	if err := ValidateNotNil(assignment, "role assignment"); err != nil {
		return err
	}

	var errs []error
	if err := ValidateUUIDRequired(assignment.WorkflowInstanceID, "workflow instance ID"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringRequired(assignment.RoleName, "role name"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringLength(assignment.RoleName, "role name", MaxRoleNameLength); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateAssignmentType(assignment.AssignedToType); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringRequired(assignment.AssignedToID, "assigned to ID"); err != nil {
		errs = append(errs, err)
	}
	if err := ValidateStringLength(assignment.AssignedToID, "assigned to ID", MaxAssignedToIDLength); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return CombineErrors(errs...)
	}

	return nil
}

// BulkCreate creates multiple role assignments at once
func (s *RoleAssignmentService) BulkCreate(assignments []RoleAssignment) error {
	if len(assignments) == 0 {
		return errors.New("no assignments provided")
	}

	// Validate all assignments
	for i, assignment := range assignments {
		if err := s.ValidateAssignment(&assignment); err != nil {
			return fmt.Errorf("assignment %d validation failed: %w", i, err)
		}
	}

	return s.db.Create(&assignments).Error
}

// GetActiveAssignments retrieves all active role assignments for a workflow instance
func (s *RoleAssignmentService) GetActiveAssignments(instanceID *uuid.UUID) ([]RoleAssignment, error) {
	var assignments []RoleAssignment
	err := s.db.Where("workflow_instance_id = ? AND is_active = ?", instanceID, true).
		Find(&assignments).Error

	return assignments, err
}

// FindAssigneeForRole finds the assignee for a specific role in a workflow instance
func (s *RoleAssignmentService) FindAssigneeForRole(instanceID *uuid.UUID, roleName string) (*RoleAssignment, error) {
	var assignment RoleAssignment
	err := s.db.Where("workflow_instance_id = ? AND role_name = ? AND is_active = ?",
		instanceID, roleName, true).
		First(&assignment).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("no active assignment found for role %s in instance %d", roleName, instanceID)
		}
		return nil, err
	}

	return &assignment, nil
}
