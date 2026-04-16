package worker

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func makeDigestJob(args WorkflowTaskDigestArgs) *river.Job[WorkflowTaskDigestArgs] {
	return &river.Job[WorkflowTaskDigestArgs]{Args: args}
}

func TestWorkflowTaskDigestWorker_DBRequiredAfterUserLookup(t *testing.T) {
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

	w := NewWorkflowTaskDigestWorkerWithRuntimeProvider(
		nil,
		mockEmail,
		mockRepo,
		"",
		newWorkerNotificationRuntimeProvider(mockEmail, mockSlack, func() notification.WorkerEnqueuer { return nil }),
		mockLog,
	)

	err := w.Work(ctx, makeDigestJob(WorkflowTaskDigestArgs{UserID: "user-1"}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db is nil")
	mockEmail.AssertNotCalled(t, "Send")
	mockSlack.AssertNotCalled(t, "IsEnabled")
}

func TestWorkflowTaskDigestWorker_UserNotFound_Skips(t *testing.T) {
	ctx := context.Background()

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	mockLog := zap.NewNop().Sugar()

	mockRepo.On("FindUserByID", ctx, "missing").Return(NotificationUser{}, errors.New("not found"))

	w := NewWorkflowTaskDigestWorkerWithRuntimeProvider(
		nil,
		mockEmail,
		mockRepo,
		"",
		newWorkerNotificationRuntimeProvider(mockEmail, mockSlack, func() notification.WorkerEnqueuer { return nil }),
		mockLog,
	)

	err := w.Work(ctx, makeDigestJob(WorkflowTaskDigestArgs{UserID: "missing"}))
	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
	mockSlack.AssertNotCalled(t, "IsEnabled")
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
