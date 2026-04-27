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

func TestNormalizeNotificationKind(t *testing.T) {
	kind, ok := NormalizeNotificationKind(" workflow_execution_failed ")
	assert.True(t, ok)
	assert.Equal(t, NotificationKindWorkflowExecutionFailed, kind)
}

func TestNormalizeSystemNotificationKind(t *testing.T) {
	kind, ok := NormalizeSystemNotificationKind(" EVIDENCE_DIGEST ")
	assert.True(t, ok)
	assert.Equal(t, NotificationKindEvidenceDigest, kind)

	kind, ok = NormalizeSystemNotificationKind(" workflow_task_assigned ")
	assert.False(t, ok)
	assert.Equal(t, Kind(""), kind)
}

func TestSystemNotificationKinds(t *testing.T) {
	assert.Equal(t, []string{string(NotificationKindEvidenceDigest), string(NotificationKindWorkflowExecutionFailed)}, SystemNotificationKinds())
}
