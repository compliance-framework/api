package notification

import (
	"strings"
)

const (
	SubscriptionGateUngated = ""

	SubscriptionGateEvidenceDigest    = "evidence_digest"
	SubscriptionGateTaskAvailable     = "task_available"
	SubscriptionGateTaskDailyDigest   = "task_daily_digest"
	SubscriptionGateRiskNotifications = "risk_notifications"

	SubscriptionGateEvidenceDigestWire    = "evidenceDigest"
	SubscriptionGateTaskAvailableWire     = "taskAvailable"
	SubscriptionGateTaskDailyDigestWire   = "taskDailyDigest"
	SubscriptionGateRiskNotificationsWire = "riskNotifications"

	subscriptionGateEvidenceDigestWireNormalized    = "evidencedigest"
	subscriptionGateTaskAvailableWireNormalized     = "taskavailable"
	subscriptionGateTaskDailyDigestWireNormalized   = "taskdailydigest"
	subscriptionGateRiskNotificationsWireNormalized = "risknotifications"
)

var subscriptionGateInputAliases = map[string]string{
	SubscriptionGateEvidenceDigest:                  SubscriptionGateEvidenceDigest,
	SubscriptionGateTaskAvailable:                   SubscriptionGateTaskAvailable,
	SubscriptionGateTaskDailyDigest:                 SubscriptionGateTaskDailyDigest,
	SubscriptionGateRiskNotifications:               SubscriptionGateRiskNotifications,
	subscriptionGateEvidenceDigestWireNormalized:    SubscriptionGateEvidenceDigest,
	subscriptionGateTaskAvailableWireNormalized:     SubscriptionGateTaskAvailable,
	subscriptionGateTaskDailyDigestWireNormalized:   SubscriptionGateTaskDailyDigest,
	subscriptionGateRiskNotificationsWireNormalized: SubscriptionGateRiskNotifications,
}

var subscriptionGateWireValues = map[string]string{
	SubscriptionGateEvidenceDigest:    SubscriptionGateEvidenceDigestWire,
	SubscriptionGateTaskAvailable:     SubscriptionGateTaskAvailableWire,
	SubscriptionGateTaskDailyDigest:   SubscriptionGateTaskDailyDigestWire,
	SubscriptionGateRiskNotifications: SubscriptionGateRiskNotificationsWire,
}

var systemSubscriptionGates = []string{
	SubscriptionGateEvidenceDigest,
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeSubscriptionGate canonicalizes a subscription gate and verifies support.
func NormalizeSubscriptionGate(subscriptionGate string) (string, bool) {
	normalized := normalizeToken(subscriptionGate)
	if normalized == "" {
		return "", false
	}

	canonical, ok := subscriptionGateInputAliases[normalized]
	if !ok {
		return "", false
	}

	return canonical, true
}

// WireSubscriptionGate returns camelCase for a supported subscription gate.
func WireSubscriptionGate(subscriptionGate string) (string, bool) {
	canonical, ok := NormalizeSubscriptionGate(subscriptionGate)
	if !ok {
		return "", false
	}

	wireValue, ok := subscriptionGateWireValues[canonical]
	if !ok {
		return "", false
	}

	return wireValue, true
}

func SystemSubscriptionGates() []string {
	return append([]string(nil), systemSubscriptionGates...)
}
