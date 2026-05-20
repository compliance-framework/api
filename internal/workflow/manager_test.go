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

type MockWorkflowExecutionEvidenceCreator struct {
	mock.Mock
}

func (m *MockWorkflowExecutionEvidenceCreator) AddWorkflowExecutionEvidence(ctx context.Context, workflowExecutionID *uuid.UUID, status string) error {
	args := m.Called(ctx, workflowExecutionID, status)
	return args.Error(0)
}

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

// TestManager_StartWorkflowExecution_EmitsStartedEvidenceViaConstructor verifies that the
// evidence creator passed to NewManager is used to emit "started" evidence at trigger time.
// This is the regression test for the production wiring gap: neither cmd/run.go nor
// worker/service.go ever calls SetEvidenceCreator, so evidence is silently dropped in production.
// Fix: assign the evidenceCreator constructor arg to m.evidenceCreator inside NewManager.
func TestManager_StartWorkflowExecution_EmitsStartedEvidenceViaConstructor(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	instanceID := uuid.New()
	executionID := uuid.New()

	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}
	mockEvidenceCreator := &MockWorkflowExecutionEvidenceCreator{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,                 // notificationEnqueuer
		mockEvidenceCreator, // evidenceCreator
	)

	mockWorkflowInstService.On("GetByID", &instanceID).Return(&workflows.WorkflowInstance{IsActive: true}, nil).Once()
	mockWorkflowExecService.On("Create", mock.AnythingOfType("*workflows.WorkflowExecution")).
		Run(func(args mock.Arguments) {
			exec := args.Get(0).(*workflows.WorkflowExecution)
			id := executionID
			exec.ID = &id
		}).
		Return(nil).Once()
	mockClient.On("InsertMany", ctx, mock.Anything).Return([]*rivertype.JobInsertResult{}, nil).Once()
	mockEvidenceCreator.On("AddWorkflowExecutionEvidence", ctx, &executionID, "started").Return(nil).Once()

	opts := StartWorkflowOptions{TriggeredBy: workflows.TriggerManual.String()}

	execution, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.NoError(t, err)
	require.NotNil(t, execution)

	mockEvidenceCreator.AssertExpectations(t)
	mockWorkflowExecService.AssertExpectations(t)
	mockWorkflowInstService.AssertExpectations(t)
}

// TestManager_StartWorkflowExecution_EmitsStartedEvidenceImmediately verifies that "started"
// evidence is emitted at trigger time (when the execution is created as pending), not deferred
// until the async transition to in_progress. Without this guarantee there is a timing window
// where an execution exists in the system but has no evidence of having started.
func TestManager_StartWorkflowExecution_EmitsStartedEvidenceImmediately(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop().Sugar()

	instanceID := uuid.New()
	executionID := uuid.New()

	mockClient := &MockRiverClient{}
	mockWorkflowExecService := &MockWorkflowExecutionService{}
	mockWorkflowInstService := &MockWorkflowInstanceService{}
	mockStepExecService := &MockStepExecutionService{}
	mockEvidenceCreator := &MockWorkflowExecutionEvidenceCreator{}

	manager := NewManager(
		mockClient,
		mockWorkflowExecService,
		mockWorkflowInstService,
		mockStepExecService,
		logger,
		nil,
		nil,
	)
	manager.SetEvidenceCreator(mockEvidenceCreator)

	mockWorkflowInstService.On("GetByID", &instanceID).Return(&workflows.WorkflowInstance{IsActive: true}, nil).Once()

	// Simulate database assigning an ID on Create (normally done by UUIDModel.BeforeCreate GORM hook).
	mockWorkflowExecService.On("Create", mock.AnythingOfType("*workflows.WorkflowExecution")).
		Run(func(args mock.Arguments) {
			exec := args.Get(0).(*workflows.WorkflowExecution)
			id := executionID
			exec.ID = &id
		}).
		Return(nil).Once()

	mockClient.On("InsertMany", ctx, mock.Anything).Return([]*rivertype.JobInsertResult{}, nil).Once()

	// The key assertion: evidence creator MUST be called at trigger time (while still pending),
	// not deferred to the async in_progress transition.
	mockEvidenceCreator.On("AddWorkflowExecutionEvidence", ctx, &executionID, "started").Return(nil).Once()

	opts := StartWorkflowOptions{
		TriggeredBy: workflows.TriggerManual.String(),
	}

	execution, err := manager.StartWorkflowExecution(ctx, &instanceID, opts)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// This assertion fails because Manager currently does not call the evidence creator —
	// "started" evidence is only emitted later when the River job transitions to in_progress.
	mockEvidenceCreator.AssertExpectations(t)
	mockWorkflowExecService.AssertExpectations(t)
	mockWorkflowInstService.AssertExpectations(t)
}
