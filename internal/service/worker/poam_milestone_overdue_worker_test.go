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

func TestMilestoneOverdueReminderWorker_SlackSubscribedUser_SendsSlack(t *testing.T) {
	ctx := context.Background()
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	logger := zap.NewNop().Sugar()
	recipientUserID := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"

	user := NotificationUser{
		ID:          recipientUserID,
		Email:       "owner@example.com",
		FirstName:   "Owner",
		LastName:    "Person",
		SlackUserID: "USLACKPOAM5",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateRiskNotifications, Channels: []string{"slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, recipientUserID).Return(user, nil)
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACKPOAM5", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-poam-milestone-1"}, nil).Once()

	worker := NewMilestoneOverdueReminderWorker(
		mockRepo,
		"https://app.example.com",
		newTestPoamNotificationServiceFactory(mockEmail, mockSlack),
		logger,
	)

	err := worker.Work(ctx, makeWorkerJob(MilestoneOverdueReminderArgs{
		MilestoneID:     uuid.MustParse("66666666-6666-6666-6666-666666666666"),
		PoamItemID:      uuid.MustParse("77777777-7777-7777-7777-777777777777"),
		RecipientUserID: uuid.MustParse(recipientUserID),
		MilestoneTitle:  "Deploy patched AMI",
		PoamTitle:       "Patch Vulnerable Dependencies",
		SspDisplayName:  "CoreBanking SSP",
		DueDate:         "2026-04-15T00:00:00Z",
		PoamURL:         "https://app.example.com/poam-items/77777777-7777-7777-7777-777777777777",
		WeeklyBucket:    "2026-W16",
	}))

	assert.NoError(t, err)
	mockEmail.AssertNotCalled(t, "UseTemplate", mock.Anything, mock.Anything)
	mockEmail.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

func TestMilestoneOverdueReminderWorker_EmailAndSlackSubscribedUser_SendsBoth(t *testing.T) {
	ctx := context.Background()
	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	logger := zap.NewNop().Sugar()
	recipientUserID := "ffffffff-ffff-ffff-ffff-ffffffffffff"

	user := NotificationUser{
		ID:          recipientUserID,
		Email:       "owner@example.com",
		FirstName:   "Owner",
		LastName:    "Person",
		SlackUserID: "USLACKPOAM6",
		NotificationSubscriptions: []NotificationSubscription{
			{NotificationType: notification.SubscriptionGateRiskNotifications, Channels: []string{"email", "slack"}},
		},
	}
	mockRepo.On("FindUserByID", ctx, recipientUserID).Return(user, nil)
	mockEmail.On("UseTemplate", "poam-milestone-overdue-reminder", mock.Anything).Return("<html>milestone</html>", "milestone text", nil).Once()
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com").Once()
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-poam-milestone-1"}, nil).Once()
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "USLACKPOAM6", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil && msg.Text != ""
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-poam-milestone-2"}, nil).Once()

	worker := NewMilestoneOverdueReminderWorker(
		mockRepo,
		"https://app.example.com",
		newTestPoamNotificationServiceFactory(mockEmail, mockSlack),
		logger,
	)

	err := worker.Work(ctx, makeWorkerJob(MilestoneOverdueReminderArgs{
		MilestoneID:     uuid.MustParse("88888888-8888-8888-8888-888888888888"),
		PoamItemID:      uuid.MustParse("99999999-9999-9999-9999-999999999999"),
		RecipientUserID: uuid.MustParse(recipientUserID),
		MilestoneTitle:  "Rotate certificates",
		PoamTitle:       "Patch Vulnerable Dependencies",
		SspDisplayName:  "Payments SSP",
		DueDate:         "2026-05-01T00:00:00Z",
		PoamURL:         "https://app.example.com/poam-items/99999999-9999-9999-9999-999999999999",
		WeeklyBucket:    "2026-W16",
	}))

	assert.NoError(t, err)
	mockEmail.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}
