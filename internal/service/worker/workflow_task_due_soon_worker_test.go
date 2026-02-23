package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func makeDueSoonJob(args WorkflowTaskDueSoonArgs) *river.Job[WorkflowTaskDueSoonArgs] {
	return &river.Job[WorkflowTaskDueSoonArgs]{Args: args}
}

func TestWorkflowTaskDueSoonWorker_SubscribedUser_SendsEmail(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(24 * time.Hour)

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:                           "user-1",
		Email:                        "alice@example.com",
		FirstName:                    "Alice",
		LastName:                     "Smith",
		TaskAvailableEmailSubscribed: true,
	}
	mockRepo.On("FindUserByID", ctx, "user-1").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-due-soon", mock.Anything).Return("<html>Due Soon</html>", "Due soon text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return msg.To[0] == "alice@example.com" && msg.Subject != ""
	})).Return(&types.SendResult{Success: true, MessageID: "msg-2"}, nil)

	w := NewWorkflowTaskDueSoonWorker(mockEmail, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskDueSoonArgs{
		UserID:                "user-1",
		StepExecutionID:       "step-1",
		StepTitle:             "Submit Evidence",
		WorkflowTitle:         "SOC2 Audit",
		WorkflowInstanceTitle: "SOC2 2026",
		StepURL:               "https://app.example.com/steps/step-1",
		DueDate:               dueDate,
	}

	err := w.Work(ctx, makeDueSoonJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowTaskDueSoonWorker_UnsubscribedUser_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:                           "user-2",
		Email:                        "bob@example.com",
		FirstName:                    "Bob",
		TaskAvailableEmailSubscribed: false,
	}
	mockRepo.On("FindUserByID", ctx, "user-2").Return(user, nil)

	w := NewWorkflowTaskDueSoonWorker(mockEmail, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskDueSoonArgs{
		UserID:          "user-2",
		StepExecutionID: "step-2",
		StepTitle:       "Submit Evidence",
		WorkflowTitle:   "SOC2 Audit",
		DueDate:         time.Now().Add(24 * time.Hour),
	}

	err := w.Work(ctx, makeDueSoonJob(args))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskDueSoonWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockRepo.On("FindUserByID", ctx, "missing-user").Return(NotificationUser{}, errors.New("not found"))

	w := NewWorkflowTaskDueSoonWorker(mockEmail, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskDueSoonArgs{
		UserID:          "missing-user",
		StepExecutionID: "step-3",
		DueDate:         time.Now().Add(24 * time.Hour),
	}

	err := w.Work(ctx, makeDueSoonJob(args))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskDueSoonWorker_TemplateError_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:                           "user-3",
		Email:                        "carol@example.com",
		FirstName:                    "Carol",
		TaskAvailableEmailSubscribed: true,
	}
	mockRepo.On("FindUserByID", ctx, "user-3").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-due-soon", mock.Anything).Return("", "", errors.New("template broken"))
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")

	w := NewWorkflowTaskDueSoonWorker(mockEmail, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskDueSoonArgs{
		UserID:          "user-3",
		StepExecutionID: "step-4",
		StepTitle:       "Submit Evidence",
		WorkflowTitle:   "SOC2 Audit",
		DueDate:         time.Now().Add(24 * time.Hour),
	}

	err := w.Work(ctx, makeDueSoonJob(args))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow-task-due-soon template")
}
