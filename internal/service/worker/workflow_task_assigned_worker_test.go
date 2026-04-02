package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindUserByID(ctx context.Context, userID string) (NotificationUser, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(NotificationUser), args.Error(1)
}

func makeTaskAssignedJob(args WorkflowTaskAssignedArgs) *river.Job[WorkflowTaskAssignedArgs] {
	return &river.Job[WorkflowTaskAssignedArgs]{Args: args}
}

func TestWorkflowTaskAssignedWorker_SubscribedUser_SendsEmail(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-1",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Smith",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.NotificationTypeTaskAvailable, Channels: []string{"email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-1").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return msg.To[0] == "alice@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-1"}, nil)

	w := NewWorkflowTaskAssignedWorker(mockEmail, nil, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskAssignedArgs{
		UserID:                "user-1",
		StepExecutionID:       "step-1",
		StepTitle:             "Review Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-1",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowTaskAssignedWorker_UnsubscribedUser_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-2",
		Email:     "bob@example.com",
		FirstName: "Bob",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.NotificationTypeTaskAvailable, Channels: []string{}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-2").Return(user, nil)

	w := NewWorkflowTaskAssignedWorker(mockEmail, nil, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskAssignedArgs{
		UserID:          "user-2",
		StepExecutionID: "step-2",
		StepTitle:       "Review Policy",
		WorkflowTitle:   "Annual Audit",
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	// Send must NOT be called
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskAssignedWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockRepo.On("FindUserByID", ctx, "missing-user").Return(NotificationUser{}, errors.New("not found"))

	w := NewWorkflowTaskAssignedWorker(mockEmail, nil, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskAssignedArgs{
		UserID:          "missing-user",
		StepExecutionID: "step-3",
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	// Should return nil (non-fatal skip)
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestWorkflowTaskAssignedWorker_TemplateError_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-3",
		Email:     "carol@example.com",
		FirstName: "Carol",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.NotificationTypeTaskAvailable, Channels: []string{"email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-3").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("", "", errors.New("template broken"))
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")

	w := NewWorkflowTaskAssignedWorker(mockEmail, nil, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskAssignedArgs{
		UserID:          "user-3",
		StepExecutionID: "step-4",
		StepTitle:       "Review",
		WorkflowTitle:   "Audit",
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow-task-assigned template")
}

func TestWorkflowTaskAssignedWorker_MultiChannel_IncludingEmail_SendsEmail(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:          "user-4",
		Email:       "dora@example.com",
		FirstName:   "Dora",
		SlackUserID: "U12345",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.NotificationTypeTaskAvailable, Channels: []string{"slack", "email"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-4").Return(user, nil)
	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return msg.To[0] == "dora@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-4"}, nil).Once()
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "U12345", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-msg-1"}, nil).Once()

	w := NewWorkflowTaskAssignedWorker(mockEmail, mockSlack, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskAssignedArgs{
		UserID:                "user-4",
		StepExecutionID:       "step-4",
		StepTitle:             "Review Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-4",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestWorkflowTaskAssignedWorker_EmailAssignee_SendsDirectEmailWithoutUserLookup(t *testing.T) {
	ctx := context.Background()
	dueDate := time.Now().Add(48 * time.Hour)

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockEmail.On("UseTemplate", "workflow-task-assigned", mock.Anything).Return("<html>Task</html>", "Task text", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "external@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-external"}, nil).Once()

	w := NewWorkflowTaskAssignedWorker(mockEmail, nil, mockRepo, "http://localhost:8000", mockLog)

	args := WorkflowTaskAssignedArgs{
		AssignedToType:        "email",
		UserID:                "external@example.com",
		StepExecutionID:       "step-external",
		StepTitle:             "Submit Policy",
		WorkflowTitle:         "Annual Audit",
		WorkflowInstanceTitle: "Audit 2026",
		StepURL:               "https://app.example.com/steps/step-external",
		DueDate:               &dueDate,
	}

	err := w.Work(ctx, makeTaskAssignedJob(args))
	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockRepo.AssertNotCalled(t, "FindUserByID", mock.Anything, mock.Anything)
}
