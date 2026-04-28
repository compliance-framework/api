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

func TestNormalizeSubscriptionGate(t *testing.T) {
	normalized, ok := NormalizeSubscriptionGate(" Task_Available ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateTaskAvailable, normalized)
}

func TestNormalizeSubscriptionGate_EvidenceDigest(t *testing.T) {
	normalized, ok := NormalizeSubscriptionGate(" Evidence_Digest ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateEvidenceDigest, normalized)
}

func TestNormalizeSubscriptionGate_TaskDailyDigest(t *testing.T) {
	normalized, ok := NormalizeSubscriptionGate(" Task_Daily_Digest ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateTaskDailyDigest, normalized)
}

func TestNormalizeSubscriptionGate_RiskNotifications(t *testing.T) {
	normalized, ok := NormalizeSubscriptionGate(" Risk_Notifications ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateRiskNotifications, normalized)
}

func TestNormalizeSubscriptionGate_CamelCaseAliases(t *testing.T) {
	normalized, ok := NormalizeSubscriptionGate(" taskAvailable ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateTaskAvailable, normalized)

	normalized, ok = NormalizeSubscriptionGate(" evidenceDigest ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateEvidenceDigest, normalized)

	normalized, ok = NormalizeSubscriptionGate(" taskDailyDigest ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateTaskDailyDigest, normalized)

	normalized, ok = NormalizeSubscriptionGate(" riskNotifications ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateRiskNotifications, normalized)
}

func TestWireSubscriptionGate(t *testing.T) {
	wireType, ok := WireSubscriptionGate(" task_available ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateTaskAvailableWire, wireType)

	wireType, ok = WireSubscriptionGate(" evidenceDigest ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateEvidenceDigestWire, wireType)

	wireType, ok = WireSubscriptionGate(" taskDailyDigest ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateTaskDailyDigestWire, wireType)

	wireType, ok = WireSubscriptionGate(" risk_notifications ")
	assert.True(t, ok)
	assert.Equal(t, SubscriptionGateRiskNotificationsWire, wireType)
}

func TestNormalizeSubscriptionGate_Invalid(t *testing.T) {
	normalized, ok := NormalizeSubscriptionGate("risk_opened")
	assert.False(t, ok)
	assert.Equal(t, "", normalized)
}

func TestNormalizeSystemNotificationName(t *testing.T) {
	normalized, ok := NormalizeSystemNotificationName(" workflowExecutionFailed ")
	assert.True(t, ok)
	assert.Equal(t, SystemNotificationNameWorkflowExecutionFailed, normalized)

	normalized, ok = NormalizeSystemNotificationName(" TASK_AVAILABLE ")
	assert.True(t, ok)
	assert.Equal(t, SystemNotificationNameTaskAvailable, normalized)
}

func TestNormalizeSystemNotificationNameRejectsUnsupportedName(t *testing.T) {
	normalized, ok := NormalizeSystemNotificationName("risk_opened")
	assert.False(t, ok)
	assert.Equal(t, "", normalized)
}

func TestSystemNotificationNames(t *testing.T) {
	assert.Equal(t, []string{
		SystemNotificationNameEvidenceDigest,
		SystemNotificationNameWorkflowExecutionFailed,
	}, SystemNotificationNames())
}
