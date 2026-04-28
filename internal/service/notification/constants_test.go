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

func TestNormalizeNotificationType_EvidenceDigest(t *testing.T) {
	normalized, ok := NormalizeNotificationType(" Evidence_Digest ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeEvidenceDigest, normalized)
}

func TestNormalizeNotificationType_TaskDailyDigest(t *testing.T) {
	normalized, ok := NormalizeNotificationType(" Task_Daily_Digest ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeTaskDailyDigest, normalized)
}

func TestNormalizeNotificationType_RiskNotifications(t *testing.T) {
	normalized, ok := NormalizeNotificationType(" Risk_Notifications ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeRiskNotifications, normalized)
}

func TestNormalizeNotificationType_CamelCaseAliases(t *testing.T) {
	normalized, ok := NormalizeNotificationType(" taskAvailable ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeTaskAvailable, normalized)

	normalized, ok = NormalizeNotificationType(" evidenceDigest ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeEvidenceDigest, normalized)

	normalized, ok = NormalizeNotificationType(" taskDailyDigest ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeTaskDailyDigest, normalized)

	normalized, ok = NormalizeNotificationType(" riskNotifications ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeRiskNotifications, normalized)
}

func TestWireNotificationType(t *testing.T) {
	wireType, ok := WireNotificationType(" task_available ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeTaskAvailableWire, wireType)

	wireType, ok = WireNotificationType(" evidenceDigest ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeEvidenceDigestWire, wireType)

	wireType, ok = WireNotificationType(" taskDailyDigest ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeTaskDailyDigestWire, wireType)

	wireType, ok = WireNotificationType(" risk_notifications ")
	assert.True(t, ok)
	assert.Equal(t, NotificationTypeRiskNotificationsWire, wireType)
}

func TestNormalizeNotificationType_Invalid(t *testing.T) {
	normalized, ok := NormalizeNotificationType("risk_opened")
	assert.False(t, ok)
	assert.Equal(t, "", normalized)
}

func TestSystemNotificationTypes(t *testing.T) {
	assert.Equal(t, []string{NotificationTypeEvidenceDigest}, SystemNotificationTypes())
}
