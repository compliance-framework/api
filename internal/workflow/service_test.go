package workflow

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRiverClient mocks the River client for testing
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

func TestNewWorkflowService(t *testing.T) {
	executor := &DAGExecutor{}

	t.Run("Success", func(t *testing.T) {
		mockClient := &MockRiverClient{}

		service, err := NewWorkflowService(executor, mockClient)

		require.NoError(t, err)
		assert.NotNil(t, service)
		assert.Equal(t, executor, service.executor)
		assert.Equal(t, mockClient, service.riverClient)
	})

	t.Run("ErrorWhenRiverClientIsNil", func(t *testing.T) {
		service, err := NewWorkflowService(executor, nil)

		require.Error(t, err)
		assert.Nil(t, service)
		assert.Contains(t, err.Error(), "river client is required")
	})
}

func TestWorkflowService_EnqueueWorkflowExecution(t *testing.T) {
	executor := &DAGExecutor{}
	mockClient := &MockRiverClient{}

	service, err := NewWorkflowService(executor, mockClient)
	require.NoError(t, err)

	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()
		executionID := uuid.New()
		triggeredBy := "manual"
		triggeredByID := "user-123"

		// Mock successful job insertion
		mockClient.On("InsertMany", ctx, mock.AnythingOfType("[]river.InsertManyParams")).Return(
			[]*rivertype.JobInsertResult{},
			nil,
		).Once()

		err := service.EnqueueWorkflowExecution(ctx, &executionID, triggeredBy, triggeredByID)

		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
	})

	t.Run("ErrorWhenInsertFails", func(t *testing.T) {
		ctx := context.Background()
		executionID := uuid.New()
		triggeredBy := "manual"
		triggeredByID := "user-123"

		// Mock failed job insertion
		mockClient.On("InsertMany", ctx, mock.AnythingOfType("[]river.InsertManyParams")).Return(
			nil,
			assert.AnError,
		).Once()

		err := service.EnqueueWorkflowExecution(ctx, &executionID, triggeredBy, triggeredByID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to enqueue workflow execution job")
		mockClient.AssertExpectations(t)
	})
}

func TestWorkflowService_GetExecutor(t *testing.T) {
	executor := &DAGExecutor{}
	mockClient := &MockRiverClient{}

	service, err := NewWorkflowService(executor, mockClient)
	require.NoError(t, err)

	retrievedExecutor := service.GetExecutor()

	assert.Equal(t, executor, retrievedExecutor)
}
