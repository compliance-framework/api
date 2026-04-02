package worker

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/stretchr/testify/assert"
)

func TestNotificationUserNotificationChannels_NormalizesAndDeduplicates(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: " Task_Available ",
				Channels:         []string{" Email ", "slack", "EMAIL", "pagerduty"},
			},
			{
				NotificationType: notification.NotificationTypeTaskAvailable,
				Channels:         []string{"SLACK", "email"},
			},
			{
				NotificationType: "task_due_soon",
				Channels:         []string{"email"},
			},
		},
	}

	channels := user.NotificationChannels(notification.NotificationTypeTaskAvailable)
	assert.Equal(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, channels)
}

func TestNotificationUserNotificationChannels_InvalidRequestedType(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.NotificationTypeTaskAvailable,
				Channels:         []string{notification.DeliveryChannelEmail},
			},
		},
	}

	assert.Nil(t, user.NotificationChannels("task_due_soon"))
}
