package workflow

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRoleAssignmentService is a mock implementation of RoleAssignmentServiceInterface
type MockRoleAssignmentService struct {
	mock.Mock
}

func (m *MockRoleAssignmentService) FindAssigneeForRole(instanceID *uuid.UUID, roleName string) (*workflows.RoleAssignment, error) {
	args := m.Called(instanceID, roleName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*workflows.RoleAssignment), args.Error(1)
}

func (m *MockRoleAssignmentService) GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]workflows.RoleAssignment, error) {
	args := m.Called(instanceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]workflows.RoleAssignment), args.Error(1)
}

func TestResolveStepAssignees(t *testing.T) {
	instanceID := uuid.New()
	instance := &workflows.WorkflowInstance{
		UUIDModel: relational.UUIDModel{ID: &instanceID},
	}

	step1ID := uuid.New()
	step2ID := uuid.New()
	step3ID := uuid.New()

	steps := []workflows.WorkflowStepDefinition{
		{
			UUIDModel:       relational.UUIDModel{ID: &step1ID},
			ResponsibleRole: "admin",
		},
		{
			UUIDModel:       relational.UUIDModel{ID: &step2ID},
			ResponsibleRole: "viewer",
		},
		{
			UUIDModel:       relational.UUIDModel{ID: &step3ID},
			ResponsibleRole: "editor",
		},
	}

	mockRoleService := new(MockRoleAssignmentService)
	assignmentService := NewAssignmentService(mockRoleService)

	// Mock responses
	// Step 1: Role "admin" -> User "user-1"
	mockRoleService.On("FindAssigneeForRole", &instanceID, "admin").Return(&workflows.RoleAssignment{
		AssignedToType: "user",
		AssignedToID:   "user-1",
		IsActive:       true,
	}, nil)

	// Step 2: Role "viewer" -> Group "group-1"
	mockRoleService.On("FindAssigneeForRole", &instanceID, "viewer").Return(&workflows.RoleAssignment{
		AssignedToType: "group",
		AssignedToID:   "group-1",
		IsActive:       true,
	}, nil)

	// Step 3: Role "editor" -> Not found or inactive
	// Case 3a: Role not found (error)
	// mockRoleService.On("FindAssigneeForRole", &instanceID, "editor").Return(nil, errors.New("role not found"))

	// Let's test inactive role for Step 3
	mockRoleService.On("FindAssigneeForRole", &instanceID, "editor").Return(&workflows.RoleAssignment{
		AssignedToType: "user",
		AssignedToID:   "user-2",
		IsActive:       false,
	}, nil)

	assignments, err := assignmentService.ResolveStepAssignees(context.Background(), instance, steps)
	assert.NoError(t, err)
	assert.Len(t, assignments, 2)

	// Check Step 1
	assignee1, ok1 := assignments[step1ID]
	assert.True(t, ok1)
	assert.Equal(t, "user", assignee1.Type)
	assert.Equal(t, "user-1", assignee1.ID)

	// Check Step 2
	assignee2, ok2 := assignments[step2ID]
	assert.True(t, ok2)
	assert.Equal(t, "group", assignee2.Type)
	assert.Equal(t, "group-1", assignee2.ID)

	// Check Step 3 (should not be assigned because inactive)
	_, ok3 := assignments[step3ID]
	assert.False(t, ok3)

	mockRoleService.AssertExpectations(t)
}

func TestResolveStepAssignees_NoRole(t *testing.T) {
	instanceID := uuid.New()
	instance := &workflows.WorkflowInstance{
		UUIDModel: relational.UUIDModel{ID: &instanceID},
	}

	step1ID := uuid.New()
	steps := []workflows.WorkflowStepDefinition{
		{
			UUIDModel:       relational.UUIDModel{ID: &step1ID},
			ResponsibleRole: "", // Empty role
		},
	}

	mockRoleService := new(MockRoleAssignmentService)
	assignmentService := NewAssignmentService(mockRoleService)

	assignments, err := assignmentService.ResolveStepAssignees(context.Background(), instance, steps)
	assert.NoError(t, err)
	assert.Empty(t, assignments)

	mockRoleService.AssertNotCalled(t, "FindAssigneeForRole")
}
