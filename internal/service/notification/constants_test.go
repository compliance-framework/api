package notification

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeDeliveryChannels(t *testing.T) {
	normalized, invalid := NormalizeDeliveryChannels([]string{" Email ", "slack", "EMAIL"})
	assert.Equal(t, []string{DeliveryChannelEmail, DeliveryChannelSlack}, normalized)
	assert.Empty(t, invalid)
}

func TestNormalizeDeliveryChannels_Invalid(t *testing.T) {
	normalized, invalid := NormalizeDeliveryChannels([]string{"sms", "email", "pagerduty", "SMS"})
	assert.Equal(t, []string{DeliveryChannelEmail}, normalized)
	assert.Equal(t, []string{"pagerduty", "sms"}, invalid)
}

func TestNormalizeDeliveryChannels_EmptyIsInvalid(t *testing.T) {
	normalized, invalid := NormalizeDeliveryChannels([]string{"email", " ", ""})
	assert.Equal(t, []string{DeliveryChannelEmail}, normalized)
	assert.Equal(t, 1, len(invalid))
}

func TestNormalizeNotificationType(t *testing.T) {
	normalized, ok := NormalizeNotificationType(" Task_Available ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeTaskAvailable, normalized)
}

func TestNormalizeNotificationType_Invalid(t *testing.T) {
	normalized, ok := NormalizeNotificationType("risk_opened")
	assert.False(t, ok)
	assert.Equal(t, "", normalized)
}
