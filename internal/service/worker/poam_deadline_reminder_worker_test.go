package worker

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

func TestPoamDeadlineReminderWorker_SlackSubscribedUser_SendsSlack(t *testing.T) {
	ctx := context.Background()
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	logger := zap.NewNop().Sugar()
	recipientUserID := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	user := NotificationUser{
		ID:          recipientUserID,
		Email:       "owner@example.com",
		FirstName:   "Owner",
		LastName:    "Person",
		SlackUserID: "USLACKPOAM1",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.NotificationTypeRiskNotifications, Channels: []string{"slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, recipientUserID).Return(user, nil)
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACKPOAM1", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-poam-1"}, nil).Once()

	worker := NewPoamDeadlineReminderWorker(
		mockRepo,
		"https://app.example.com",
		newTestPoamNotificationServiceFactory(mockEmail, mockSlack),
		logger,
	)

	err := worker.Work(ctx, makeWorkerJob(PoamDeadlineReminderArgs{
		PoamItemID:           uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		RecipientUserID:      uuid.MustParse(recipientUserID),
		PoamTitle:            "Patch Vulnerable Dependencies",
		SspDisplayName:       "CoreBanking SSP",
		CurrentStatus:        "in-progress",
		Deadline:             "2026-04-15T00:00:00Z",
		MilestoneCount:       3,
		PoamURL:              "https://app.example.com/poam-items/11111111-1111-1111-1111-111111111111",
		ReminderWindowBucket: "2026-04-17",
	}))

	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "UseTemplate", mock.Anything, mock.Anything)
	mockEmail.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestPoamDeadlineReminderWorker_EmailAndSlackSubscribedUser_SendsBoth(t *testing.T) {
	ctx := context.Background()
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	logger := zap.NewNop().Sugar()
	recipientUserID := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	user := NotificationUser{
		ID:          recipientUserID,
		Email:       "owner@example.com",
		FirstName:   "Owner",
		LastName:    "Person",
		SlackUserID: "USLACKPOAM2",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.NotificationTypeRiskNotifications, Channels: []string{"email", "slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, recipientUserID).Return(user, nil)
	mockEmail.On("UseTemplate", "poam-deadline-reminder", mock.Anything).Return("<html>reminder</html>", "reminder text", nil).Once()
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com").Once()
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-poam-1"}, nil).Once()
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACKPOAM2", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-poam-2"}, nil).Once()

	worker := NewPoamDeadlineReminderWorker(
		mockRepo,
		"https://app.example.com",
		newTestPoamNotificationServiceFactory(mockEmail, mockSlack),
		logger,
	)

	err := worker.Work(ctx, makeWorkerJob(PoamDeadlineReminderArgs{
		PoamItemID:           uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		RecipientUserID:      uuid.MustParse(recipientUserID),
		PoamTitle:            "Rotate Certificates",
		SspDisplayName:       "Payments SSP",
		CurrentStatus:        "open",
		Deadline:             "2026-05-01T00:00:00Z",
		MilestoneCount:       1,
		PoamURL:              "https://app.example.com/poam-items/22222222-2222-2222-2222-222222222222",
		ReminderWindowBucket: "2026-04-17",
	}))

	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}
