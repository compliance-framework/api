package workflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
)

// Assignee represents a user or group assigned to a step
type Assignee struct {
	Type string // user, group, email
	ID   string // UUID or email address
}

// AssignmentService handles logic for resolving step assignments
type AssignmentService struct {
	roleAssignmentService RoleAssignmentServiceInterface
}

// NewAssignmentService creates a new assignment service
func NewAssignmentService(roleAssignmentService RoleAssignmentServiceInterface) *AssignmentService {
	return &AssignmentService{
		roleAssignmentService: roleAssignmentService,
	}
}

// ResolveStepAssignees resolves assignees for a list of step definitions based on role assignments
func (s *AssignmentService) ResolveStepAssignees(ctx context.Context, instance *workflows.WorkflowInstance, stepDefinitions []workflows.WorkflowStepDefinition) (map[uuid.UUID]Assignee, error) {
	assignments := make(map[uuid.UUID]Assignee)

	for _, stepDef := range stepDefinitions {
		// Skip if no responsible role is defined
		if stepDef.ResponsibleRole == "" {
			continue
		}

		// Look up role assignment
		roleAssignment, err := s.roleAssignmentService.FindAssigneeForRole(instance.ID, stepDef.ResponsibleRole)
		if err != nil {
			if errors.Is(err, workflows.ErrRoleAssignmentNotFound) {
				continue
			}
			return nil, fmt.Errorf("failed to find assignee for role %s: %w", stepDef.ResponsibleRole, err)
		}

		if roleAssignment != nil && roleAssignment.IsActive {
			assignments[*stepDef.ID] = Assignee{
				Type: roleAssignment.AssignedToType,
				ID:   roleAssignment.AssignedToID,
			}
		}
	}

	return assignments, nil
}
