package workflow

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockStepExecutionService is a mock for workflows.StepExecutionService
type MockStepExecutionService struct {
	mock.Mock
}

func (m *MockStepExecutionService) Create(stepExecution *workflows.StepExecution) error {
	args := m.Called(stepExecution)
	return args.Error(0)
}

func (m *MockStepExecutionService) GetByID(id *uuid.UUID) (*workflows.StepExecution, error) {
	args := m.Called(id)
	return args.Get(0).(*workflows.StepExecution), args.Error(1)
}

func (m *MockStepExecutionService) GetByWorkflowExecutionID(executionID *uuid.UUID) ([]workflows.StepExecution, error) {
	args := m.Called(executionID)
	return args.Get(0).([]workflows.StepExecution), args.Error(1)
}

func (m *MockStepExecutionService) UpdateStatus(ctx context.Context, id *uuid.UUID, status string) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockStepExecutionService) Fail(id *uuid.UUID, reason string) error {
	args := m.Called(id, reason)
	return args.Error(0)
}

func (m *MockStepExecutionService) CanUnblock(id *uuid.UUID) (bool, error) {
	args := m.Called(id)
	return args.Bool(0), args.Error(1)
}

func (m *MockStepExecutionService) Unblock(id *uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockWorkflowExecutionService is a mock for workflows.WorkflowExecutionService
type MockWorkflowExecutionService struct {
	mock.Mock
}

func (m *MockWorkflowExecutionService) GetByID(id *uuid.UUID) (*workflows.WorkflowExecution, error) {
	args := m.Called(id)
	return args.Get(0).(*workflows.WorkflowExecution), args.Error(1)
}

func (m *MockWorkflowExecutionService) Create(execution *workflows.WorkflowExecution) error {
	args := m.Called(execution)
	return args.Error(0)
}

func (m *MockWorkflowExecutionService) GetByWorkflowInstanceID(instanceID *uuid.UUID) ([]workflows.WorkflowExecution, error) {
	args := m.Called(instanceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]workflows.WorkflowExecution), args.Error(1)
}

func (m *MockWorkflowExecutionService) UpdateStatus(ctx context.Context, id *uuid.UUID, status string) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockWorkflowExecutionService) Cancel(id *uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockWorkflowExecutionService) Fail(id *uuid.UUID, reason string) error {
	args := m.Called(id, reason)
	return args.Error(0)
}

func (m *MockWorkflowExecutionService) FailIfNotTerminal(ctx context.Context, id *uuid.UUID, reason string) (bool, error) {
	args := m.Called(ctx, id, reason)
	return args.Bool(0), args.Error(1)
}

// MockWorkflowStepDefinitionService is a mock for workflows.WorkflowStepDefinitionService
type MockWorkflowStepDefinitionService struct {
	mock.Mock
}

func (m *MockWorkflowStepDefinitionService) GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error) {
	args := m.Called(workflowDefID)
	return args.Get(0).([]workflows.WorkflowStepDefinition), args.Error(1)
}

func (m *MockWorkflowStepDefinitionService) GetDependencies(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error) {
	args := m.Called(stepID)
	return args.Get(0).([]workflows.WorkflowStepDefinition), args.Error(1)
}

func (m *MockWorkflowStepDefinitionService) GetByID(id *uuid.UUID) (*workflows.WorkflowStepDefinition, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*workflows.WorkflowStepDefinition), args.Error(1)
}

func (m *MockWorkflowStepDefinitionService) GetDependentSteps(stepID *uuid.UUID) ([]workflows.WorkflowStepDefinition, error) {
	args := m.Called(stepID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]workflows.WorkflowStepDefinition), args.Error(1)
}

// MockAssignmentService is a mock for AssignmentServiceInterface
type MockAssignmentService struct {
	mock.Mock
}

func (m *MockAssignmentService) ResolveStepAssignees(ctx context.Context, instance *workflows.WorkflowInstance, stepDefinitions []workflows.WorkflowStepDefinition) (map[uuid.UUID]Assignee, error) {
	args := m.Called(ctx, instance, stepDefinitions)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[uuid.UUID]Assignee), args.Error(1)
}

type MockNotificationEnqueuer struct {
	mock.Mock
}

func (m *MockNotificationEnqueuer) EnqueueWorkflowTaskAssigned(ctx context.Context, stepExecution *workflows.StepExecution) error {
	args := m.Called(ctx, stepExecution)
	return args.Error(0)
}

func (m *MockNotificationEnqueuer) EnqueueWorkflowExecutionFailed(ctx context.Context, execution *workflows.WorkflowExecution) error {
	args := m.Called(ctx, execution)
	return args.Error(0)
}

func TestNewDAGExecutor(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.Default()

	// Create executor using interfaces
	executor := NewDAGExecutor(
		mockStepExecService,
		mockWorkflowExecService,
		mockStepDefService,
		mockAssignmentService,
		logger,
		nil,
	)

	assert.NotNil(t, executor)
	assert.Equal(t, mockStepExecService, executor.stepExecutionService)
	assert.Equal(t, mockWorkflowExecService, executor.workflowExecutionService)
	assert.Equal(t, mockStepDefService, executor.stepDefinitionService)
	assert.Equal(t, mockAssignmentService, executor.assignmentService)
	assert.Equal(t, logger, executor.logger)
}

func TestResolveStepGraceDays_Preference(t *testing.T) {
	defGrace := 9
	instanceGrace := 5
	stepGrace := 2

	workflowExecution := &workflows.WorkflowExecution{
		WorkflowInstance: &workflows.WorkflowInstance{
			GracePeriodDays: &instanceGrace,
			WorkflowDefinition: &workflows.WorkflowDefinition{
				GracePeriodDays: &defGrace,
			},
		},
	}

	stepWithOverride := workflows.WorkflowStepDefinition{GracePeriodDays: &stepGrace}
	assert.Equal(t, stepGrace, resolveStepGraceDays(workflowExecution, stepWithOverride))

	stepWithoutOverride := workflows.WorkflowStepDefinition{}
	assert.Equal(t, instanceGrace, resolveStepGraceDays(workflowExecution, stepWithoutOverride))

	workflowExecution.WorkflowInstance.GracePeriodDays = nil
	assert.Equal(t, defGrace, resolveStepGraceDays(workflowExecution, stepWithoutOverride))
}

func TestInitializeWorkflow_Success(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger, nil)

	// Setup test data
	workflowExecutionID := uuid.New()
	workflowDefID := uuid.New()
	instanceID := uuid.New()

	stepDefID1 := uuid.New()
	stepDefID2 := uuid.New()

	workflowExecution := &workflows.WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: &workflowExecutionID},
		WorkflowInstanceID: &instanceID,
		Status:             "pending",
		WorkflowInstance: &workflows.WorkflowInstance{
			UUIDModel:            relational.UUIDModel{ID: &instanceID},
			WorkflowDefinitionID: &workflowDefID,
		},
	}

	stepDefinitions := []workflows.WorkflowStepDefinition{
		{UUIDModel: relational.UUIDModel{ID: &stepDefID1}, Name: "Step 1"},
		{UUIDModel: relational.UUIDModel{ID: &stepDefID2}, Name: "Step 2"},
	}

	// Setup mocks
	mockWorkflowExecService.On("GetByID", &workflowExecutionID).Return(workflowExecution, nil)
	mockStepDefService.On("GetByWorkflowDefinitionID", &workflowDefID).Return(stepDefinitions, nil)
	mockStepDefService.On("GetDependencies", &stepDefID1).Return([]workflows.WorkflowStepDefinition{}, nil)
	mockStepDefService.On("GetDependencies", &stepDefID2).Return([]workflows.WorkflowStepDefinition{workflows.WorkflowStepDefinition{UUIDModel: relational.UUIDModel{ID: &stepDefID1}}}, nil)
	mockStepExecService.On("GetByWorkflowExecutionID", &workflowExecutionID).Return([]workflows.StepExecution{}, nil)
	mockWorkflowExecService.On("UpdateStatus", mock.Anything, &workflowExecutionID, "in_progress").Return(nil)

	// Mock assignment service
	mockAssignmentService.On("ResolveStepAssignees", mock.Anything, mock.Anything, mock.Anything).Return(map[uuid.UUID]Assignee{}, nil)

	// Mock step execution creation
	mockStepExecService.On("Create", mock.MatchedBy(func(se *workflows.StepExecution) bool {
		// Set the ID for the created step execution
		if se.ID == nil {
			id := uuid.New()
			se.ID = &id
		}
		return true
	})).Return(nil)

	// Initialize workflow
	ctx := context.Background()
	err := executor.InitializeWorkflow(ctx, &workflowExecutionID)

	// Verify results
	require.NoError(t, err)

	// Verify all mocks were called
	mockWorkflowExecService.AssertExpectations(t)
	mockStepDefService.AssertExpectations(t)
	mockStepExecService.AssertExpectations(t)
	mockAssignmentService.AssertExpectations(t)
}

func TestInitializeWorkflow_Failure(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger, nil)

	// Setup test data
	workflowExecutionID := uuid.New()

	// Setup mocks - simulate failure in getting workflow definition
	mockWorkflowExecService.On("GetByID", &workflowExecutionID).Return((*workflows.WorkflowExecution)(nil), fmt.Errorf("workflow execution not found"))

	// Initialize workflow
	ctx := context.Background()
	err := executor.InitializeWorkflow(ctx, &workflowExecutionID)

	// Verify results - should fail due to workflow execution not found
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow execution not found")

	// Verify all mocks were called
	mockWorkflowExecService.AssertExpectations(t)
}

func TestProcessStepCompletion_PassesRequestContextToNotificationEnqueuer(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	mockNotificationEnqueuer := &MockNotificationEnqueuer{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	executor := NewDAGExecutor(
		mockStepExecService,
		mockWorkflowExecService,
		mockStepDefService,
		mockAssignmentService,
		logger,
		mockNotificationEnqueuer,
	)

	stepExecutionID := uuid.New()
	workflowExecutionID := uuid.New()
	completedStepDefID := uuid.New()
	dependentStepDefID := uuid.New()
	dependentStepExecID := uuid.New()

	completedStep := &workflows.StepExecution{
		UUIDModel:                relational.UUIDModel{ID: &stepExecutionID},
		WorkflowExecutionID:      &workflowExecutionID,
		WorkflowStepDefinitionID: &completedStepDefID,
		Status:                   StatusCompleted.String(),
	}
	dependentExec := workflows.StepExecution{
		UUIDModel:                relational.UUIDModel{ID: &dependentStepExecID},
		WorkflowExecutionID:      &workflowExecutionID,
		WorkflowStepDefinitionID: &dependentStepDefID,
		Status:                   StatusBlocked.String(),
	}
	reloadedDependent := &workflows.StepExecution{
		UUIDModel:                relational.UUIDModel{ID: &dependentStepExecID},
		WorkflowExecutionID:      &workflowExecutionID,
		WorkflowStepDefinitionID: &dependentStepDefID,
		Status:                   StatusPending.String(),
	}

	mockStepExecService.On("GetByID", &stepExecutionID).Return(completedStep, nil).Once()
	mockStepDefService.On("GetDependentSteps", &completedStepDefID).Return([]workflows.WorkflowStepDefinition{
		{UUIDModel: relational.UUIDModel{ID: &dependentStepDefID}},
	}, nil).Once()
	mockStepExecService.On("GetByWorkflowExecutionID", &workflowExecutionID).Return([]workflows.StepExecution{
		dependentExec,
	}, nil).Twice()
	mockStepExecService.On("CanUnblock", &dependentStepExecID).Return(true, nil).Once()
	mockStepExecService.On("Unblock", &dependentStepExecID).Return(nil).Once()
	mockStepExecService.On("GetByID", &dependentStepExecID).Return(reloadedDependent, nil).Once()

	type ctxKey string
	const traceKey ctxKey = "trace_id"
	ctx := context.WithValue(context.Background(), traceKey, "trace-123")
	mockNotificationEnqueuer.On(
		"EnqueueWorkflowTaskAssigned",
		mock.MatchedBy(func(c context.Context) bool {
			return c != nil && c.Value(traceKey) == "trace-123"
		}),
		reloadedDependent,
	).Return(nil).Once()

	err := executor.ProcessStepCompletion(ctx, &stepExecutionID)
	require.NoError(t, err)

	mockStepExecService.AssertExpectations(t)
	mockStepDefService.AssertExpectations(t)
	mockNotificationEnqueuer.AssertExpectations(t)
}
