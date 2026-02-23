package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func makeDigestJob(args WorkflowTaskDigestArgs) *river.Job[WorkflowTaskDigestArgs] {
	return &river.Job[WorkflowTaskDigestArgs]{Args: args}
}

func TestWorkflowTaskDigestWorker_UnsubscribedUser_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:                        "user-1",
		Email:                     "alice@example.com",
		FirstName:                 "Alice",
		TaskDailyDigestSubscribed: false,
	}
	mockRepo.On("FindUserByID", ctx, "user-1").Return(user, nil)

	w := NewWorkflowTaskDigestWorker(nil, mockEmail, mockRepo, "", mockLog)

	err := w.Work(ctx, makeDigestJob(WorkflowTaskDigestArgs{UserID: "user-1"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskDigestWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockRepo.On("FindUserByID", ctx, "missing").Return(NotificationUser{}, errors.New("not found"))

	w := NewWorkflowTaskDigestWorker(nil, mockEmail, mockRepo, "", mockLog)

	err := w.Work(ctx, makeDigestJob(WorkflowTaskDigestArgs{UserID: "missing"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}
