package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/api/internal/service/notification"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func makeDigestJob(args WorkflowTaskDigestArgs) *river.Job[WorkflowTaskDigestArgs] {
	return &river.Job[WorkflowTaskDigestArgs]{Args: args}
}

func TestWorkflowTaskDigestWorker_UnsubscribedUser_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	user := NotificationUser{
		ID:        "user-1",
		Email:     "alice@example.com",
		FirstName: "Alice",
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.NotificationTypeTaskDailyDigest,
				Channels:         []string{},
			},
		},
	}
	mockRepo.On("FindUserByID", ctx, "user-1").Return(user, nil)

	w := NewWorkflowTaskDigestWorker(nil, mockEmail, mockSlack, mockRepo, "", mockLog)

	err := w.Work(ctx, makeDigestJob(WorkflowTaskDigestArgs{UserID: "user-1"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
	mockSlack.AssertNotCalled(t, "IsEnabled")
	mockSlack.AssertNotCalled(t, "SendMessage", mock.Anything, mock.Anything, mock.Anything)
}

func TestWorkflowTaskDigestWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockRepo.On("FindUserByID", ctx, "missing").Return(NotificationUser{}, errors.New("not found"))

	w := NewWorkflowTaskDigestWorker(nil, mockEmail, mockSlack, mockRepo, "", mockLog)

	err := w.Work(ctx, makeDigestJob(WorkflowTaskDigestArgs{UserID: "missing"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
	mockSlack.AssertNotCalled(t, "IsEnabled")
	mockSlack.AssertNotCalled(t, "SendMessage", mock.Anything, mock.Anything, mock.Anything)
}

func TestWorkflowTaskDigestWorker_SendSlack_NilService_Skips(t *testing.T) {
	ctx := context.Background()

	core, observedLogs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()

	w := &WorkflowTaskDigestWorker{
		slackService: nil,
		logger:       logger,
	}
	user := NotificationUser{
		ID:          "user-1",
		FirstName:   "Alice",
		SlackUserID: "U12345",
	}
	data := digestNotificationData{
		UserName:     "Alice",
		PeriodLabel:  "Daily digest",
		PendingTasks: nil,
		OverdueTasks: nil,
		MyTasksURL:   "https://app.example.com/my-tasks",
	}

	err := w.sendSlack(ctx, "user-1", user, data)
	assert.NoError(t, err)

	entries := observedLogs.FilterMessage("WorkflowTaskDigestWorker: slack service not configured, skipping").All()
	assert.Len(t, entries, 1)
	assert.Equal(t, "user-1", entries[0].ContextMap()["user_id"])
}

func TestWorkflowTaskDigestWorker_SendSlack_DisabledService_Skips(t *testing.T) {
	ctx := context.Background()

	mockSlack := &MockSlackService{}
	mockSlack.On("IsEnabled").Return(false).Once()

	core, observedLogs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()

	w := &WorkflowTaskDigestWorker{
		slackService: mockSlack,
		logger:       logger,
	}
	user := NotificationUser{
		ID:          "user-2",
		FirstName:   "Bob",
		SlackUserID: "U67890",
	}
	data := digestNotificationData{
		UserName:     "Bob",
		PeriodLabel:  "Daily digest",
		PendingTasks: nil,
		OverdueTasks: nil,
		MyTasksURL:   "https://app.example.com/my-tasks",
	}

	err := w.sendSlack(ctx, "user-2", user, data)
	assert.NoError(t, err)

	mockSlack.AssertExpectations(t)
	mockSlack.AssertNotCalled(t, "SendMessage", mock.Anything, mock.Anything, mock.Anything)

	entries := observedLogs.FilterMessage("WorkflowTaskDigestWorker: slack service not configured, skipping").All()
	assert.Len(t, entries, 1)
	assert.Equal(t, "user-2", entries[0].ContextMap()["user_id"])
}

func TestWorkflowTaskDigestWorker_SendSlack_NoSlackLink_Skips(t *testing.T) {
	ctx := context.Background()

	mockSlack := &MockSlackService{}
	mockSlack.On("IsEnabled").Return(true).Once()

	core, observedLogs := observer.New(zap.DebugLevel)
	logger := zap.New(core).Sugar()

	w := &WorkflowTaskDigestWorker{
		slackService: mockSlack,
		logger:       logger,
	}
	user := NotificationUser{
		ID:          "user-3",
		FirstName:   "Charlie",
		SlackUserID: "   ",
	}
	data := digestNotificationData{
		UserName:     "Charlie",
		PeriodLabel:  "Daily digest",
		PendingTasks: nil,
		OverdueTasks: nil,
		MyTasksURL:   "https://app.example.com/my-tasks",
	}

	err := w.sendSlack(ctx, "user-3", user, data)
	assert.NoError(t, err)

	mockSlack.AssertExpectations(t)
	mockSlack.AssertNotCalled(t, "SendMessage", mock.Anything, mock.Anything, mock.Anything)

	entries := observedLogs.FilterMessage("WorkflowTaskDigestWorker: user has no Slack link, skipping").All()
	assert.Len(t, entries, 1)
	assert.Equal(t, "user-3", entries[0].ContextMap()["user_id"])
}

func TestWorkflowTaskDigestWorker_SendSlack_SendMessageError_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockSlack := &MockSlackService{}
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "UERR", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: false}, errors.New("slack API down")).Once()

	w := &WorkflowTaskDigestWorker{
		slackService: mockSlack,
		logger:       zap.NewNop().Sugar(),
	}
	user := NotificationUser{
		ID:          "user-4",
		FirstName:   "Dana",
		SlackUserID: "UERR",
	}
	data := digestNotificationData{
		UserName:     "Dana",
		PeriodLabel:  "Daily digest",
		PendingTasks: nil,
		OverdueTasks: nil,
		MyTasksURL:   "https://app.example.com/my-tasks",
	}

	err := w.sendSlack(ctx, "user-4", user, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send workflow-task-digest slack message")
	assert.Contains(t, err.Error(), "slack API down")

	mockSlack.AssertExpectations(t)
}

func TestWorkflowTaskDigestWorker_SendSlack_UnsuccessfulResult_ReturnsError(t *testing.T) {
	ctx := context.Background()

	mockSlack := &MockSlackService{}
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "UFAIL", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{
		Success: false,
		Error:   "rate_limited",
	}, nil).Once()

	w := &WorkflowTaskDigestWorker{
		slackService: mockSlack,
		logger:       zap.NewNop().Sugar(),
	}
	user := NotificationUser{
		ID:          "user-5",
		FirstName:   "Evan",
		SlackUserID: "UFAIL",
	}
	data := digestNotificationData{
		UserName:     "Evan",
		PeriodLabel:  "Daily digest",
		PendingTasks: nil,
		OverdueTasks: nil,
		MyTasksURL:   "https://app.example.com/my-tasks",
	}

	err := w.sendSlack(ctx, "user-5", user, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow-task-digest slack message send failed: rate_limited")

	mockSlack.AssertExpectations(t)
}

func TestToSlackDigestTasks_EmptyInput_ReturnsNil(t *testing.T) {
	assert.Nil(t, toSlackDigestTasks(nil))
	assert.Nil(t, toSlackDigestTasks([]DigestTask{}))
}

func TestToSlackDigestTasks_NilDueDate_ConvertsToEmptyString(t *testing.T) {
	tasks := []DigestTask{
		{
			StepTitle:             "Review Policy",
			WorkflowTitle:         "Annual Audit",
			WorkflowInstanceTitle: "Audit 2026",
			DueDate:               nil,
			StepURL:               "https://app.example.com/steps/1",
		},
	}

	converted := toSlackDigestTasks(tasks)
	assert.Len(t, converted, 1)
	assert.Equal(t, "Review Policy", converted[0].StepTitle)
	assert.Equal(t, "Annual Audit", converted[0].WorkflowTitle)
	assert.Equal(t, "Audit 2026", converted[0].WorkflowInstanceTitle)
	assert.Equal(t, "", converted[0].DueDate)
	assert.Equal(t, "https://app.example.com/steps/1", converted[0].StepURL)
}

func TestToSlackDigestTasks_MultipleTasks_ConvertsAllFields(t *testing.T) {
	dueDateOne := "2026-04-03"
	dueDateTwo := "2026-04-04"
	tasks := []DigestTask{
		{
			StepTitle:             "Submit Evidence",
			WorkflowTitle:         "SOC2",
			WorkflowInstanceTitle: "Q2 Readiness",
			DueDate:               &dueDateOne,
			StepURL:               "https://app.example.com/steps/2",
		},
		{
			StepTitle:             "Approve Control",
			WorkflowTitle:         "ISO",
			WorkflowInstanceTitle: "ISO 2026",
			DueDate:               &dueDateTwo,
			StepURL:               "https://app.example.com/steps/3",
		},
	}

	converted := toSlackDigestTasks(tasks)
	assert.Len(t, converted, 2)

	assert.Equal(t, "Submit Evidence", converted[0].StepTitle)
	assert.Equal(t, "SOC2", converted[0].WorkflowTitle)
	assert.Equal(t, "Q2 Readiness", converted[0].WorkflowInstanceTitle)
	assert.Equal(t, "2026-04-03", converted[0].DueDate)
	assert.Equal(t, "https://app.example.com/steps/2", converted[0].StepURL)

	assert.Equal(t, "Approve Control", converted[1].StepTitle)
	assert.Equal(t, "ISO", converted[1].WorkflowTitle)
	assert.Equal(t, "ISO 2026", converted[1].WorkflowInstanceTitle)
	assert.Equal(t, "2026-04-04", converted[1].DueDate)
	assert.Equal(t, "https://app.example.com/steps/3", converted[1].StepURL)
}
