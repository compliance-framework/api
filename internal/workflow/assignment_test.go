package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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
	assignmentService := NewAssignmentService(mockRoleService, nil, zap.NewNop().Sugar())

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
	assignmentService := NewAssignmentService(mockRoleService, nil, zap.NewNop().Sugar())

	assignments, err := assignmentService.ResolveStepAssignees(context.Background(), instance, steps)
	assert.NoError(t, err)
	assert.Empty(t, assignments)

	mockRoleService.AssertNotCalled(t, "FindAssigneeForRole")
}

func setupAssignmentServiceTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&relational.User{}))
	for _, entity := range workflows.GetWorkflowEntities() {
		require.NoError(t, db.AutoMigrate(entity))
	}

	return db
}

func createAssignmentServiceGraph(t *testing.T, db *gorm.DB) (*workflows.WorkflowExecution, *workflows.WorkflowStepDefinition, *workflows.StepExecution) {
	t.Helper()

	workflowDef := &workflows.WorkflowDefinition{Name: "WF", Version: "1.0"}
	require.NoError(t, db.Create(workflowDef).Error)

	sysID := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "instance",
		SystemSecurityPlanID: &sysID,
	}
	require.NoError(t, db.Create(instance).Error)

	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
		TriggeredBy:        "manual",
	}
	require.NoError(t, db.Create(execution).Error)

	stepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Step 1",
		ResponsibleRole:      "engineer",
	}
	require.NoError(t, db.Create(stepDef).Error)

	stepExec := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: stepDef.ID,
		Status:                   "pending",
		AssignedToType:           "group",
		AssignedToID:             "old-group",
	}
	require.NoError(t, db.Create(stepExec).Error)

	return execution, stepDef, stepExec
}

func TestReassignStep(t *testing.T) {
	db := setupAssignmentServiceTestDB(t)
	roleService := new(MockRoleAssignmentService)
	service := NewAssignmentService(roleService, db, zap.NewNop().Sugar())

	_, _, stepExec := createAssignmentServiceGraph(t, db)

	reassignedByID := uuid.New()
	reassignedByUser := &relational.User{
		UUIDModel:  relational.UUIDModel{ID: &reassignedByID},
		Email:      "reassigner@example.com",
		FirstName:  "Re",
		LastName:   "Assigner",
		IsActive:   true,
		AuthMethod: "local",
	}
	require.NoError(t, db.Create(reassignedByUser).Error)

	newAssigneeID := uuid.New()
	newAssigneeUser := &relational.User{
		UUIDModel:  relational.UUIDModel{ID: &newAssigneeID},
		Email:      "new-assignee@example.com",
		FirstName:  "New",
		LastName:   "Assignee",
		IsActive:   true,
		AuthMethod: "local",
	}
	require.NoError(t, db.Create(newAssigneeUser).Error)

	err := service.ReassignStep(
		context.Background(),
		*stepExec.ID,
		Assignee{Type: "user", ID: newAssigneeID.String()},
		"capacity balancing",
		&reassignedByID,
		reassignedByUser.Email,
	)
	require.NoError(t, err)

	var updated workflows.StepExecution
	require.NoError(t, db.First(&updated, stepExec.ID).Error)
	assert.Equal(t, "user", updated.AssignedToType)
	assert.Equal(t, newAssigneeID.String(), updated.AssignedToID)
	assert.NotNil(t, updated.AssignedAt)

	var history []workflows.StepReassignmentHistory
	require.NoError(t, db.Where("step_execution_id = ?", stepExec.ID).Find(&history).Error)
	require.Len(t, history, 1)
	assert.Equal(t, "group", history[0].PreviousAssignedToType)
	assert.Equal(t, "old-group", history[0].PreviousAssignedToID)
	assert.Equal(t, "user", history[0].NewAssignedToType)
	assert.Equal(t, newAssigneeID.String(), history[0].NewAssignedToID)
	assert.Equal(t, "capacity balancing", history[0].Reason)
	assert.NotNil(t, history[0].ReassignedByUserID)
	assert.Equal(t, reassignedByID, *history[0].ReassignedByUserID)
	assert.Equal(t, reassignedByUser.Email, history[0].ReassignedByEmail)
}

func TestReassignStep_RejectsInvalidStatus(t *testing.T) {
	db := setupAssignmentServiceTestDB(t)
	roleService := new(MockRoleAssignmentService)
	service := NewAssignmentService(roleService, db, zap.NewNop().Sugar())

	_, _, stepExec := createAssignmentServiceGraph(t, db)

	testStatuses := []string{"completed", "failed", "skipped"}
	for _, status := range testStatuses {
		stepExec.Status = status
		require.NoError(t, db.Save(stepExec).Error)

		err := service.ReassignStep(
			context.Background(),
			*stepExec.ID,
			Assignee{Type: "group", ID: "new-group"},
			"",
			nil,
			"actor@example.com",
		)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrReassignmentNotAllowed))
	}
}

func TestReassignStep_AllowsOverdueStatus(t *testing.T) {
	db := setupAssignmentServiceTestDB(t)
	roleService := new(MockRoleAssignmentService)
	service := NewAssignmentService(roleService, db, zap.NewNop().Sugar())

	_, _, stepExec := createAssignmentServiceGraph(t, db)
	stepExec.Status = workflows.StepStatusOverdue.String()
	require.NoError(t, db.Save(stepExec).Error)

	err := service.ReassignStep(
		context.Background(),
		*stepExec.ID,
		Assignee{Type: "group", ID: "new-group"},
		"",
		nil,
		"actor@example.com",
	)
	require.NoError(t, err)

	var updated workflows.StepExecution
	require.NoError(t, db.First(&updated, stepExec.ID).Error)
	assert.Equal(t, "group", updated.AssignedToType)
	assert.Equal(t, "new-group", updated.AssignedToID)
}

func TestReassignStep_RejectsInvalidAssigneeAndMissingUser(t *testing.T) {
	db := setupAssignmentServiceTestDB(t)
	roleService := new(MockRoleAssignmentService)
	service := NewAssignmentService(roleService, db, zap.NewNop().Sugar())

	_, _, stepExec := createAssignmentServiceGraph(t, db)

	err := service.ReassignStep(
		context.Background(),
		*stepExec.ID,
		Assignee{Type: "invalid", ID: "x"},
		"",
		nil,
		"actor@example.com",
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAssignee))

	missingUserID := uuid.New()
	err = service.ReassignStep(
		context.Background(),
		*stepExec.ID,
		Assignee{Type: "user", ID: missingUserID.String()},
		"",
		nil,
		"actor@example.com",
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAssignee))
}

func TestBulkReassignByRole(t *testing.T) {
	db := setupAssignmentServiceTestDB(t)
	roleService := new(MockRoleAssignmentService)
	service := NewAssignmentService(roleService, db, zap.NewNop().Sugar())

	execution, stepDef, stepExec := createAssignmentServiceGraph(t, db)

	secondStepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: stepDef.WorkflowDefinitionID,
		Name:                 "Step 2",
		ResponsibleRole:      stepDef.ResponsibleRole,
	}
	require.NoError(t, db.Create(secondStepDef).Error)

	ineligibleStep := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: secondStepDef.ID,
		Status:                   "completed",
		AssignedToType:           "group",
		AssignedToID:             "old-completed",
	}
	require.NoError(t, db.Create(ineligibleStep).Error)

	otherRoleStepDef := &workflows.WorkflowStepDefinition{
		WorkflowDefinitionID: stepDef.WorkflowDefinitionID,
		Name:                 "Step 3",
		ResponsibleRole:      "reviewer",
	}
	require.NoError(t, db.Create(otherRoleStepDef).Error)

	otherRoleStep := &workflows.StepExecution{
		WorkflowExecutionID:      execution.ID,
		WorkflowStepDefinitionID: otherRoleStepDef.ID,
		Status:                   "pending",
		AssignedToType:           "group",
		AssignedToID:             "other-role",
	}
	require.NoError(t, db.Create(otherRoleStep).Error)

	newAssigneeID := uuid.New()
	user := &relational.User{
		UUIDModel:  relational.UUIDModel{ID: &newAssigneeID},
		Email:      "bulk-assignee@example.com",
		FirstName:  "Bulk",
		LastName:   "Assignee",
		IsActive:   true,
		AuthMethod: "local",
	}
	require.NoError(t, db.Create(user).Error)

	result, err := service.BulkReassignByRole(
		context.Background(),
		*execution.ID,
		stepDef.ResponsibleRole,
		Assignee{Type: "user", ID: newAssigneeID.String()},
		"bulk handoff",
		nil,
		"actor@example.com",
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, 1, result.ReassignedCount)
	require.Len(t, result.ReassignedStepExecIDs, 1)
	assert.Equal(t, *stepExec.ID, result.ReassignedStepExecIDs[0])

	var updated workflows.StepExecution
	require.NoError(t, db.First(&updated, stepExec.ID).Error)
	assert.Equal(t, "user", updated.AssignedToType)
	assert.Equal(t, newAssigneeID.String(), updated.AssignedToID)

	var unchanged workflows.StepExecution
	require.NoError(t, db.First(&unchanged, ineligibleStep.ID).Error)
	assert.Equal(t, "old-completed", unchanged.AssignedToID)

	var otherRole workflows.StepExecution
	require.NoError(t, db.First(&otherRole, otherRoleStep.ID).Error)
	assert.Equal(t, "other-role", otherRole.AssignedToID)
}
