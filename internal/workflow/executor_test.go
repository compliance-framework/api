package workflow

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"testing"
	"time"

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
	)

	assert.NotNil(t, executor)
	assert.Equal(t, mockStepExecService, executor.stepExecutionService)
	assert.Equal(t, mockWorkflowExecService, executor.workflowExecutionService)
	assert.Equal(t, mockStepDefService, executor.stepDefinitionService)
	assert.Equal(t, mockAssignmentService, executor.assignmentService)
	assert.Equal(t, logger, executor.logger)
}

func TestInitializeExecutionState(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger)

	// Create test step definitions
	stepDefID1 := uuid.New()
	stepDefID2 := uuid.New()
	stepDefID3 := uuid.New()

	stepDefinitions := []workflows.WorkflowStepDefinition{
		{UUIDModel: relational.UUIDModel{ID: &stepDefID1}, Name: "Step 1"},
		{UUIDModel: relational.UUIDModel{ID: &stepDefID2}, Name: "Step 2"},
		{UUIDModel: relational.UUIDModel{ID: &stepDefID3}, Name: "Step 3"},
	}

	// Mock dependencies: Step 2 depends on Step 1, Step 3 depends on Step 2
	mockStepDefService.On("GetDependencies", &stepDefID1).Return([]workflows.WorkflowStepDefinition{}, nil)
	mockStepDefService.On("GetDependencies", &stepDefID2).Return([]workflows.WorkflowStepDefinition{workflows.WorkflowStepDefinition{UUIDModel: relational.UUIDModel{ID: &stepDefID1}}}, nil)
	mockStepDefService.On("GetDependencies", &stepDefID3).Return([]workflows.WorkflowStepDefinition{workflows.WorkflowStepDefinition{UUIDModel: relational.UUIDModel{ID: &stepDefID2}}}, nil)

	workflowExecutionID := uuid.New()
	state := executor.initializeExecutionState(&workflowExecutionID, stepDefinitions)

	// Verify state initialization
	assert.Equal(t, workflowExecutionID, state.WorkflowExecutionID)
	assert.Len(t, state.StepStates, 3)
	assert.Len(t, state.BlockedSteps, 2) // Steps 2 and 3 should be blocked
	assert.Contains(t, state.BlockedSteps, stepDefID2)
	assert.Contains(t, state.BlockedSteps, stepDefID3)
	assert.NotContains(t, state.BlockedSteps, stepDefID1) // Step 1 has no dependencies

	mockStepDefService.AssertExpectations(t)
}

func TestGetReadySteps(t *testing.T) {
	executor := createTestExecutor(t)

	// Create test state
	workflowExecutionID := uuid.New()
	state := &ExecutionState{
		WorkflowExecutionID: workflowExecutionID,
		StepStates:          make(map[uuid.UUID]*StepState),
		CompletedSteps:      make(map[uuid.UUID]bool),
		FailedSteps:         make(map[uuid.UUID]bool),
		RunningSteps:        make(map[uuid.UUID]bool),
		BlockedSteps:        make(map[uuid.UUID]bool),
	}

	// Create test steps
	stepID1 := uuid.New()
	stepID2 := uuid.New()
	stepID3 := uuid.New()

	// Step 1: no dependencies, should be ready
	state.StepStates[stepID1] = &StepState{
		StepDefinitionID: stepID1,
		Status:           "pending",
		Dependencies:     []uuid.UUID{},
	}

	// Step 2: depends on step 1, not ready yet
	state.StepStates[stepID2] = &StepState{
		StepDefinitionID: stepID2,
		Status:           "pending",
		Dependencies:     []uuid.UUID{stepID1},
	}

	// Step 3: depends on step 2, not ready yet
	state.StepStates[stepID3] = &StepState{
		StepDefinitionID: stepID3,
		Status:           "pending",
		Dependencies:     []uuid.UUID{stepID2},
	}

	// Initially, only step 1 should be ready
	readySteps := executor.getReadySteps(state)
	assert.Len(t, readySteps, 1)
	assert.Contains(t, readySteps, stepID1)

	// Mark step 1 as completed
	state.CompletedSteps[stepID1] = true

	// Now step 2 should be ready
	readySteps = executor.getReadySteps(state)
	assert.Len(t, readySteps, 1)
	assert.Contains(t, readySteps, stepID2)

	// Mark step 2 as completed
	state.CompletedSteps[stepID2] = true

	// Now step 3 should be ready
	readySteps = executor.getReadySteps(state)
	assert.Len(t, readySteps, 1)
	assert.Contains(t, readySteps, stepID3)
}

func TestAreDependenciesCompleted(t *testing.T) {
	executor := createTestExecutor(t)

	state := &ExecutionState{
		CompletedSteps: make(map[uuid.UUID]bool),
	}

	stepID1 := uuid.New()
	stepID2 := uuid.New()
	stepID3 := uuid.New()

	// Test with no dependencies
	dependencies := []uuid.UUID{}
	assert.True(t, executor.areDependenciesCompleted(state, dependencies))

	// Test with completed dependencies
	dependencies = []uuid.UUID{stepID1, stepID2}
	state.CompletedSteps[stepID1] = true
	state.CompletedSteps[stepID2] = true
	assert.True(t, executor.areDependenciesCompleted(state, dependencies))

	// Test with incomplete dependencies
	dependencies = []uuid.UUID{stepID1, stepID3}
	assert.False(t, executor.areDependenciesCompleted(state, dependencies))
}

func TestIsExecutionComplete(t *testing.T) {
	executor := createTestExecutor(t)

	state := &ExecutionState{
		StepStates:     make(map[uuid.UUID]*StepState),
		CompletedSteps: make(map[uuid.UUID]bool),
		FailedSteps:    make(map[uuid.UUID]bool),
	}

	stepID1 := uuid.New()
	stepID2 := uuid.New()

	// Add steps to state
	state.StepStates[stepID1] = &StepState{StepDefinitionID: stepID1}
	state.StepStates[stepID2] = &StepState{StepDefinitionID: stepID2}

	// Initially not complete
	assert.False(t, executor.isExecutionComplete(state))

	// Mark one step as completed
	state.CompletedSteps[stepID1] = true
	assert.False(t, executor.isExecutionComplete(state))

	// Mark second step as completed
	state.CompletedSteps[stepID2] = true
	assert.True(t, executor.isExecutionComplete(state))

	// Test with failure
	state.CompletedSteps[stepID2] = false
	state.FailedSteps[stepID2] = true
	assert.True(t, executor.isExecutionComplete(state))
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

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger)

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

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger)

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

func TestGetExecutionStatus(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger)

	// Setup test data
	workflowExecutionID := uuid.New()
	stepDefID1 := uuid.New()
	stepDefID2 := uuid.New()
	stepExecID1 := uuid.New()
	stepExecID2 := uuid.New()

	stepExecutions := []workflows.StepExecution{
		{
			UUIDModel:                relational.UUIDModel{ID: &stepExecID1},
			WorkflowExecutionID:      &workflowExecutionID,
			WorkflowStepDefinitionID: &stepDefID1,
			Status:                   "completed",
			StartedAt:                &time.Time{},
			CompletedAt:              &time.Time{},
		},
		{
			UUIDModel:                relational.UUIDModel{ID: &stepExecID2},
			WorkflowExecutionID:      &workflowExecutionID,
			WorkflowStepDefinitionID: &stepDefID2,
			Status:                   "in_progress",
			StartedAt:                &time.Time{},
		},
	}

	// Setup mocks
	mockStepExecService.On("GetByWorkflowExecutionID", &workflowExecutionID).Return(stepExecutions, nil)

	// Get execution status
	state, err := executor.GetExecutionStatus(&workflowExecutionID)

	// Verify results
	require.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, workflowExecutionID, state.WorkflowExecutionID)
	assert.Len(t, state.StepStates, 2)
	assert.Len(t, state.CompletedSteps, 1)
	assert.Len(t, state.RunningSteps, 1)
	assert.Contains(t, state.CompletedSteps, stepDefID1)
	assert.Contains(t, state.RunningSteps, stepDefID2)

	// Verify mocks were called
	mockStepExecService.AssertExpectations(t)
}

func TestCancelExecution(t *testing.T) {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	executor := NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger)

	// Setup test data
	workflowExecutionID := uuid.New()
	stepDefID1 := uuid.New()
	stepExecID1 := uuid.New()

	stepExecutions := []workflows.StepExecution{
		{
			UUIDModel:                relational.UUIDModel{ID: &stepExecID1},
			WorkflowExecutionID:      &workflowExecutionID,
			WorkflowStepDefinitionID: &stepDefID1,
			Status:                   "in_progress",
		},
	}

	// Setup mocks
	mockWorkflowExecService.On("UpdateStatus", mock.Anything, &workflowExecutionID, "cancelled").Return(nil)
	mockStepExecService.On("GetByWorkflowExecutionID", &workflowExecutionID).Return(stepExecutions, nil)
	mockStepExecService.On("UpdateStatus", mock.Anything, &stepExecID1, "cancelled").Return(nil)

	// Cancel execution
	ctx := context.Background()
	err := executor.CancelExecution(ctx, &workflowExecutionID)

	// Verify results
	require.NoError(t, err)

	// Verify mocks were called
	mockWorkflowExecService.AssertExpectations(t)
	mockStepExecService.AssertExpectations(t)
}

// Helper function to create a test executor
func createTestExecutor(t *testing.T) *DAGExecutor {
	mockStepExecService := &MockStepExecutionService{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockStepDefService := &MockWorkflowStepDefinitionService{}
	mockAssignmentService := &MockAssignmentService{}
	logger := log.New(bytes.NewBufferString(""), "", log.LstdFlags)

	return NewDAGExecutor(mockStepExecService, mockWorkflowExecService, mockStepDefService, mockAssignmentService, logger)
}

// Benchmark tests
func BenchmarkGetReadySteps(b *testing.B) {
	executor := createTestExecutor(&testing.T{})

	// Create a large state with many steps
	state := &ExecutionState{
		StepStates:     make(map[uuid.UUID]*StepState),
		CompletedSteps: make(map[uuid.UUID]bool),
		FailedSteps:    make(map[uuid.UUID]bool),
		RunningSteps:   make(map[uuid.UUID]bool),
		BlockedSteps:   make(map[uuid.UUID]bool),
	}

	// Create 1000 steps
	for i := 0; i < 1000; i++ {
		stepID := uuid.New()
		state.StepStates[stepID] = &StepState{
			StepDefinitionID: stepID,
			Status:           "pending",
			Dependencies:     []uuid.UUID{},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		readySteps := executor.getReadySteps(state)
		if len(readySteps) != 1000 {
			b.Fatal("Unexpected number of ready steps")
		}
	}
}

func BenchmarkAreDependenciesCompleted(b *testing.B) {
	executor := createTestExecutor(&testing.T{})

	state := &ExecutionState{
		CompletedSteps: make(map[uuid.UUID]bool),
	}

	// Create many dependencies
	dependencies := make([]uuid.UUID, 100)
	for i := 0; i < 100; i++ {
		stepID := uuid.New()
		dependencies[i] = stepID
		state.CompletedSteps[stepID] = true
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		completed := executor.areDependenciesCompleted(state, dependencies)
		if !completed {
			b.Fatal("Dependencies should be completed")
		}
	}
}
