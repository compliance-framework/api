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
				NotificationType: notification.SubscriptionGateTaskAvailable,
				Channels:         []string{"SLACK", "email"},
			},
			{
				NotificationType: "task_due_soon",
				Channels:         []string{"email"},
			},
		},
	}

	channels := user.NotificationChannels(notification.SubscriptionGateTaskAvailable)
	assert.Equal(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, channels)
}

func TestNotificationUserNotificationChannels_InvalidRequestedType(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateTaskAvailable,
				Channels:         []string{notification.DeliveryChannelEmail},
			},
		},
	}

	assert.Nil(t, user.NotificationChannels("task_due_soon"))
}

func TestSelectUserNotificationChannels_ReturnsRequestedChannelOnly(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateTaskAvailable,
				Channels:         []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
			},
		},
	}

	channels, ok := selectUserNotificationChannels(user, notification.SubscriptionGateTaskAvailable, notification.DeliveryChannelSlack)
	assert.True(t, ok)
	assert.Equal(t, []string{notification.DeliveryChannelSlack}, channels)
}

func TestSelectUserNotificationChannels_EmptyRequestedChannelReturnsAllSubscribedChannels(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateTaskAvailable,
				Channels:         []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
			},
		},
	}

	channels, ok := selectUserNotificationChannels(user, notification.SubscriptionGateTaskAvailable, "")
	assert.True(t, ok)
	assert.Equal(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, channels)
}

func TestSelectUserNotificationChannels_UnsubscribedRequestedChannelSkips(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateTaskAvailable,
				Channels:         []string{notification.DeliveryChannelEmail},
			},
		},
	}

	channels, ok := selectUserNotificationChannels(user, notification.SubscriptionGateTaskAvailable, notification.DeliveryChannelSlack)
	assert.True(t, ok)
	assert.Empty(t, channels)
}

func TestSelectUserNotificationChannels_InvalidRequestedChannelReturnsFalse(t *testing.T) {
	user := NotificationUser{
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateTaskAvailable,
				Channels:         []string{notification.DeliveryChannelEmail},
			},
		},
	}

	channels, ok := selectUserNotificationChannels(user, notification.SubscriptionGateTaskAvailable, "pagerduty")
	assert.False(t, ok)
	assert.Nil(t, channels)
}
