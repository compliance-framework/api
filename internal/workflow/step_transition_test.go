package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupStepTransitionTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&relational.User{}))
	for _, entity := range workflows.GetWorkflowEntities() {
		require.NoError(t, db.AutoMigrate(entity))
	}

	return db
}

func TestCanUserTransitionStep_QueryPath(t *testing.T) {
	db := setupStepTransitionTestDB(t)

	stepExecService := workflows.NewStepExecutionService(db, nil)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	roleAssignmentService := workflows.NewRoleAssignmentService(db)
	workflowInstanceService := workflows.NewWorkflowInstanceService(db)
	workflowDefinitionService := workflows.NewWorkflowDefinitionService(db)

	svc := NewStepTransitionService(
		stepExecService,
		stepDefService,
		workflowExecService,
		roleAssignmentService,
		workflowInstanceService,
		workflowDefinitionService,
		nil,
		db,
		nil,
		nil,
	)

	workflowDef := &workflows.WorkflowDefinition{Name: "WF", Version: "1.0"}
	require.NoError(t, db.Create(workflowDef).Error)
	sysID := uuid.New()
	instance := &workflows.WorkflowInstance{
		WorkflowDefinitionID: workflowDef.ID,
		SystemSecurityPlanID: &sysID,
		Name:                 "instance",
	}
	require.NoError(t, db.Create(instance).Error)
	execution := &workflows.WorkflowExecution{
		WorkflowInstanceID: instance.ID,
		Status:             workflows.WorkflowStatusInProgress.String(),
		TriggeredBy:        workflows.TriggerManual.String(),
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
		Status:                   workflows.StepStatusPending.String(),
	}
	require.NoError(t, db.Create(stepExec).Error)

	require.NoError(t, db.Create(&workflows.RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "engineer",
		AssignedToType:     workflows.AssignmentTypeUser.String(),
		AssignedToID:       "user-1",
		IsActive:           true,
	}).Error)

	can, err := svc.CanUserTransitionStep(stepExec.ID, "user-1", workflows.AssignmentTypeUser.String())
	require.NoError(t, err)
	assert.True(t, can)

	can, err = svc.CanUserTransitionStep(stepExec.ID, "user-2", workflows.AssignmentTypeUser.String())
	require.NoError(t, err)
	assert.False(t, can)

	missingID := uuid.New()
	_, err = svc.CanUserTransitionStep(&missingID, "user-1", workflows.AssignmentTypeUser.String())
	require.Error(t, err)
}

func TestCanUserTransitionStep_FallbackWhenDBNil(t *testing.T) {
	stepExecID := uuid.New()
	stepDefID := uuid.New()
	execID := uuid.New()
	instanceID := uuid.New()

	mockStepExec := &MockStepExecutionService{}
	mockStepDef := &MockWorkflowStepDefinitionService{}
	mockWorkflowExec := &MockWorkflowExecutionService{}
	mockRole := &MockRoleAssignmentService{}

	svc := NewStepTransitionService(
		mockStepExec,
		mockStepDef,
		mockWorkflowExec,
		mockRole,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
	)

	mockStepExec.On("GetByID", &stepExecID).Return(&workflows.StepExecution{
		UUIDModel:                relational.UUIDModel{ID: &stepExecID},
		WorkflowStepDefinitionID: &stepDefID,
		WorkflowExecutionID:      &execID,
	}, nil).Once()
	mockStepDef.On("GetByID", &stepDefID).Return(&workflows.WorkflowStepDefinition{
		UUIDModel:       relational.UUIDModel{ID: &stepDefID},
		ResponsibleRole: "engineer",
	}, nil).Once()
	mockWorkflowExec.On("GetByID", &execID).Return(&workflows.WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: &execID},
		WorkflowInstanceID: &instanceID,
	}, nil).Once()
	mockRole.On("FindAssigneeForRole", &instanceID, "engineer").Return(&workflows.RoleAssignment{
		AssignedToType: workflows.AssignmentTypeUser.String(),
		AssignedToID:   "user-1",
		IsActive:       true,
	}, nil).Once()

	can, err := svc.CanUserTransitionStep(&stepExecID, "user-1", workflows.AssignmentTypeUser.String())
	require.NoError(t, err)
	assert.True(t, can)

	mockStepExec.AssertExpectations(t)
	mockStepDef.AssertExpectations(t)
	mockWorkflowExec.AssertExpectations(t)
	mockRole.AssertExpectations(t)
}

type mockStepAssignmentService struct {
	called bool
}

func (m *mockStepAssignmentService) ReassignWithTx(tx *gorm.DB, id *uuid.UUID, assignedToType, assignedToID string, assignedAt time.Time) error {
	m.called = true
	return nil
}

func TestAssignmentService_ReassignStep_UsesStepExecutionService(t *testing.T) {
	db := setupAssignmentServiceTestDB(t)
	roleService := new(MockRoleAssignmentService)
	mockStepService := &mockStepAssignmentService{}
	service := NewAssignmentService(roleService, mockStepService, db, zap.NewNop().Sugar(), nil)

	_, _, stepExec := createAssignmentServiceGraph(t, db)

	err := service.ReassignStep(
		context.Background(),
		*stepExec.ID,
		Assignee{Type: "group", ID: "new-group"},
		"route through service",
		nil,
		"actor@example.com",
	)
	require.NoError(t, err)
	assert.True(t, mockStepService.called)
}
