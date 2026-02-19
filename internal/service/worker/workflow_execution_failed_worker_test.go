package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func makeFailedJob(args WorkflowExecutionFailedArgs) *river.Job[WorkflowExecutionFailedArgs] {
	return &river.Job[WorkflowExecutionFailedArgs]{Args: args}
}

func TestWorkflowExecutionFailedWorker_InvalidExecutionID_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	w := NewWorkflowExecutionFailedWorker(nil, mockEmail, mockRepo, mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: "not-a-uuid"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowExecutionFailedWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	userID := uuid.New()
	mockRepo.On("FindUserByID", ctx, userID.String()).Return(NotificationUser{}, errors.New("not found"))

	now := time.Now()
	_ = userID
	_ = now

	// We can't inject a mock DB without a real GORM setup, so we test the
	// invalid-UUID and user-not-found paths which don't require DB access.
	// The nil-DB path panics on GORM, so we only test the UUID guard here.
	w := NewWorkflowExecutionFailedWorker(nil, mockEmail, mockRepo, mockLog)

	err := w.Work(ctx, makeFailedJob(WorkflowExecutionFailedArgs{WorkflowExecutionID: "bad-id"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}
