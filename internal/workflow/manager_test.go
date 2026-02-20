package workflow

import (
	"context"
	"errors"
	"testing"
	"time"

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

	executionID, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.Error(t, err)
	assert.Nil(t, executionID)
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

	executionID, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.Error(t, err)
	assert.Nil(t, executionID)
	assert.False(t, errors.Is(err, ErrWorkflowExecutionAlreadyExists))
	assert.Contains(t, err.Error(), "failed to create workflow execution")
}
