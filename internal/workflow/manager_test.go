package workflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type MockRiverClient struct {
	mock.Mock
}

func (m *MockRiverClient) InsertMany(ctx context.Context, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*rivertype.JobInsertResult), args.Error(1)
}

type MockWorkflowInstanceService struct {
	mock.Mock
}

func (m *MockWorkflowInstanceService) GetByID(id *uuid.UUID) (*workflows.WorkflowInstance, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*workflows.WorkflowInstance), args.Error(1)
}

func (m *MockWorkflowInstanceService) GetDueInstances(ctx context.Context) ([]workflows.WorkflowInstance, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]workflows.WorkflowInstance), args.Error(1)
}

func (m *MockWorkflowInstanceService) AdvanceSchedule(ctx context.Context, id *uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWorkflowInstanceService) UpdateSchedule(ctx context.Context, id *uuid.UUID, nextSchedule time.Time) error {
	args := m.Called(ctx, id, nextSchedule)
	return args.Error(0)
}

func TestManager_StartWorkflowExecution_UniqueViolationScheduledReturnsAlreadyExists(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	instanceID := uuid.New()
	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)

	mockWorkflowInstService.On("GetByID", &instanceID).Return(&workflows.WorkflowInstance{IsActive: true}, nil).Once()
	mockWorkflowExecService.On("Create", mock.AnythingOfType("*workflows.WorkflowExecution")).Return(&pgconn.PgError{Code: "23505"}).Once()

	opts := StartWorkflowOptions{
		TriggeredBy: workflows.TriggerScheduled.String(),
		PeriodLabel: "2026-01",
	}

	execution, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.Error(t, err)
	assert.Nil(t, execution)
	assert.True(t, errors.Is(err, ErrWorkflowExecutionAlreadyExists))

	mockClient.AssertNotCalled(t, "InsertMany", mock.Anything, mock.Anything)
	mockWorkflowExecService.AssertExpectations(t)
	mockWorkflowInstService.AssertExpectations(t)
}

func TestManager_StartWorkflowExecution_UniqueViolationManualDoesNotReturnAlreadyExists(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	instanceID := uuid.New()
	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)

	mockWorkflowInstService.On("GetByID", &instanceID).Return(&workflows.WorkflowInstance{IsActive: true}, nil).Once()
	uniqueErr := &pgconn.PgError{Code: "23505"}
	mockWorkflowExecService.On("Create", mock.AnythingOfType("*workflows.WorkflowExecution")).Return(uniqueErr).Once()

	opts := StartWorkflowOptions{
		TriggeredBy: workflows.TriggerManual.String(),
		PeriodLabel: "2026-01",
	}

	execution, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.Error(t, err)
	assert.Nil(t, execution)
	assert.False(t, errors.Is(err, ErrWorkflowExecutionAlreadyExists))
	assert.Contains(t, err.Error(), "failed to create workflow execution")
}

// MockEvidenceCreator is a mock for workflows.WorkflowExecutionEvidenceCreator
type MockEvidenceCreator struct {
	mock.Mock
}

func (m *MockEvidenceCreator) AddWorkflowExecutionEvidence(ctx context.Context, executionID *uuid.UUID, status string) error {
	args := m.Called(ctx, executionID, status)
	return args.Error(0)
}

func TestManager_StartWorkflowExecution_EmitsStartedEvidenceAtTriggerTime(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	instanceID := uuid.New()
	executionID := uuid.New()
	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}
	mockEvidence := &MockEvidenceCreator{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)
	manager.SetEvidenceCreator(mockEvidence)

	mockWorkflowInstService.On("GetByID", &instanceID).Return(&workflows.WorkflowInstance{IsActive: true}, nil).Once()
	mockWorkflowExecService.On("Create", mock.AnythingOfType("*workflows.WorkflowExecution")).
		Run(func(args mock.Arguments) {
			exec := args.Get(0).(*workflows.WorkflowExecution)
			exec.ID = &executionID
		}).
		Return(nil).Once()
	mockClient.On("InsertMany", ctx, mock.Anything).Return([]*rivertype.JobInsertResult{}, nil).Once()
	mockEvidence.On("AddWorkflowExecutionEvidence", ctx, &executionID, "started").Return(nil).Once()

	opts := StartWorkflowOptions{
		TriggeredBy: workflows.TriggerManual.String(),
	}

	execution, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.NoError(t, err)
	require.NotNil(t, execution)

	mockEvidence.AssertCalled(t, "AddWorkflowExecutionEvidence", ctx, &executionID, "started")
	mockEvidence.AssertExpectations(t)
	mockWorkflowExecService.AssertExpectations(t)
}

func TestManager_StartWorkflowExecution_NilEvidenceCreator_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	instanceID := uuid.New()
	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)
	// evidenceCreator intentionally not set (nil)

	noopID := uuid.New()
	mockWorkflowInstService.On("GetByID", &instanceID).Return(&workflows.WorkflowInstance{IsActive: true}, nil).Once()
	mockWorkflowExecService.On("Create", mock.AnythingOfType("*workflows.WorkflowExecution")).
		Run(func(args mock.Arguments) {
			args.Get(0).(*workflows.WorkflowExecution).ID = &noopID
		}).
		Return(nil).Once()
	mockClient.On("InsertMany", ctx, mock.Anything).Return([]*rivertype.JobInsertResult{}, nil).Once()

	opts := StartWorkflowOptions{
		TriggeredBy: workflows.TriggerManual.String(),
	}

	execution, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.NoError(t, err)
	require.NotNil(t, execution)
}

func TestManager_CancelExecution_CancelsOverdueSteps(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	executionID := uuid.New()
	overdueStepID := uuid.New()
	completedStepID := uuid.New()

	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)

	mockWorkflowExecService.On("GetByID", &executionID).Return(&workflows.WorkflowExecution{
		Status: workflows.WorkflowStatusInProgress.String(),
	}, nil).Once()
	mockWorkflowExecService.On("Cancel", &executionID).Return(nil).Once()
	mockStepExecService.On("GetByWorkflowExecutionID", &executionID).Return([]workflows.StepExecution{
		{
			UUIDModel: relational.UUIDModel{ID: &overdueStepID},
			Status:    workflows.StepStatusOverdue.String(),
		},
		{
			UUIDModel: relational.UUIDModel{ID: &completedStepID},
			Status:    workflows.StepStatusCompleted.String(),
		},
	}, nil).Once()
	mockStepExecService.On("UpdateStatus", ctx, &overdueStepID, StatusCancelled.String()).Return(nil).Once()

	execution, err := manager.CancelExecution(ctx, &executionID, "user requested cancellation")
	require.NoError(t, err)
	require.NotNil(t, execution)
	assert.Equal(t, workflows.WorkflowStatusCancelled.String(), execution.Status)

	mockStepExecService.AssertNotCalled(t, "UpdateStatus", ctx, &completedStepID, StatusCancelled.String())
	mockWorkflowExecService.AssertExpectations(t)
	mockStepExecService.AssertExpectations(t)
}

func TestManager_GetExecutionMetrics_PopulatesStepMetrics(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	executionID := uuid.New()
	stepDefID := uuid.New()
	startedAt := time.Now().Add(-30 * time.Minute)
	completedAt := time.Now()

	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)

	mockWorkflowExecService.On("GetByID", &executionID).Return(&workflows.WorkflowExecution{
		UUIDModel:   relational.UUIDModel{ID: &executionID},
		Status:      workflows.WorkflowStatusCompleted.String(),
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
	}, nil).Once()

	mockStepExecService.On("GetByWorkflowExecutionID", &executionID).Return([]workflows.StepExecution{
		{
			WorkflowStepDefinitionID: &stepDefID,
			WorkflowStepDefinition: &workflows.WorkflowStepDefinition{
				UUIDModel: relational.UUIDModel{ID: &stepDefID},
				Name:      "Review Documentation",
			},
			StartedAt:   &startedAt,
			CompletedAt: &completedAt,
		},
	}, nil).Once()

	metrics, err := manager.GetExecutionMetrics(ctx, &executionID)
	require.NoError(t, err)
	require.Len(t, metrics.StepMetrics, 1)
	assert.Equal(t, stepDefID, metrics.StepMetrics[0].StepDefinitionID)
	assert.Equal(t, "Review Documentation", metrics.StepMetrics[0].StepName)
	assert.NotNil(t, metrics.StepMetrics[0].DurationMinutes)
	assert.Equal(t, startedAt, *metrics.StepMetrics[0].StartedAt)
	assert.Equal(t, completedAt, *metrics.StepMetrics[0].CompletedAt)
}

func TestManager_GetExecutionMetrics_NilWorkflowStepDefinition(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	executionID := uuid.New()
	stepDefID := uuid.New()
	startedAt := time.Now().Add(-30 * time.Minute)
	completedAt := time.Now()

	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
	)

	mockWorkflowExecService.On("GetByID", &executionID).Return(&workflows.WorkflowExecution{
		UUIDModel:   relational.UUIDModel{ID: &executionID},
		Status:      workflows.WorkflowStatusCompleted.String(),
		StartedAt:   &startedAt,
		CompletedAt: &completedAt,
	}, nil).Once()

	mockStepExecService.On("GetByWorkflowExecutionID", &executionID).Return([]workflows.StepExecution{
		{
			WorkflowStepDefinitionID: &stepDefID,
			WorkflowStepDefinition:   nil,
			StartedAt:                &startedAt,
			CompletedAt:              &completedAt,
		},
	}, nil).Once()

	metrics, err := manager.GetExecutionMetrics(ctx, &executionID)
	require.NoError(t, err)
	require.Len(t, metrics.StepMetrics, 1)
	assert.Equal(t, stepDefID, metrics.StepMetrics[0].StepDefinitionID)
	assert.Equal(t, "", metrics.StepMetrics[0].StepName)
}
