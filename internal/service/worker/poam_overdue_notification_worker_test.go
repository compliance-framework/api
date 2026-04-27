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

func TestPoamOverdueNotificationWorker_SlackSubscribedUser_SendsSlack(t *testing.T) {
	ctx := context.Background()
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	logger := zap.NewNop().Sugar()
	recipientUserID := "cccccccc-cccc-cccc-cccc-cccccccccccc"

	user := NotificationUser{
		ID:          recipientUserID,
		Email:       "owner@example.com",
		FirstName:   "Owner",
		LastName:    "Person",
		SlackUserID: "USLACKPOAM3",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateRiskNotifications, Channels: []string{"slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, recipientUserID).Return(user, nil)
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACKPOAM3", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-poam-overdue-1"}, nil).Once()

	worker := NewPoamOverdueNotificationWorker(
		mockRepo,
		"https://app.example.com",
		newTestPoamNotificationServiceFactory(mockEmail, mockSlack),
		logger,
	)

	err := worker.Work(ctx, makeWorkerJob(PoamOverdueNotificationArgs{
		PoamItemID:      uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		RecipientUserID: uuid.MustParse(recipientUserID),
		PoamTitle:       "Patch Vulnerable Dependencies",
		SspDisplayName:  "CoreBanking SSP",
		Deadline:        "2026-04-15T00:00:00Z",
		PoamURL:         "https://app.example.com/poam-items/33333333-3333-3333-3333-333333333333",
		OverdueWindow:   "2026-04-17",
	}))

	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "UseTemplate", mock.Anything, mock.Anything)
	mockEmail.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestPoamOverdueNotificationWorker_EmailAndSlackSubscribedUser_SendsBoth(t *testing.T) {
	ctx := context.Background()
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	logger := zap.NewNop().Sugar()
	recipientUserID := "dddddddd-dddd-dddd-dddd-dddddddddddd"

	user := NotificationUser{
		ID:          recipientUserID,
		Email:       "owner@example.com",
		FirstName:   "Owner",
		LastName:    "Person",
		SlackUserID: "USLACKPOAM4",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateRiskNotifications, Channels: []string{"email", "slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, recipientUserID).Return(user, nil)
	mockEmail.On("UseTemplate", "poam-overdue-notification", mock.Anything).Return("<html>overdue</html>", "overdue text", nil).Once()
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com").Once()
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-poam-overdue-1"}, nil).Once()
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACKPOAM4", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-poam-overdue-2"}, nil).Once()

	worker := NewPoamOverdueNotificationWorker(
		mockRepo,
		"https://app.example.com",
		newTestPoamNotificationServiceFactory(mockEmail, mockSlack),
		logger,
	)

	err := worker.Work(ctx, makeWorkerJob(PoamOverdueNotificationArgs{
		PoamItemID:      uuid.MustParse("44444444-4444-4444-4444-444444444444"),
		RecipientUserID: uuid.MustParse(recipientUserID),
		PoamTitle:       "Rotate Certificates",
		SspDisplayName:  "Payments SSP",
		Deadline:        "2026-05-01T00:00:00Z",
		PoamURL:         "https://app.example.com/poam-items/44444444-4444-4444-4444-444444444444",
		OverdueWindow:   "2026-04-17",
	}))

	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}
