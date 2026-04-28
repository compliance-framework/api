package notification

import (
	"strings"
)

const (
	notificationNameEvidenceDigest          = "evidence_digest"
	notificationNameTaskAvailable           = "task_available"
	notificationNameTaskDailyDigest         = "task_daily_digest"
	notificationNameRiskNotifications       = "risk_notifications"
	notificationNameWorkflowExecutionFailed = "workflow_execution_failed"

	NotificationKindEvidenceDigest          = Kind(notificationNameEvidenceDigest)
	NotificationKindWorkflowExecutionFailed = Kind(notificationNameWorkflowExecutionFailed)

	SystemNotificationNameEvidenceDigest          = notificationNameEvidenceDigest
	SystemNotificationNameTaskAvailable           = notificationNameTaskAvailable
	SystemNotificationNameTaskDailyDigest         = notificationNameTaskDailyDigest
	SystemNotificationNameRiskNotifications       = notificationNameRiskNotifications
	SystemNotificationNameWorkflowExecutionFailed = notificationNameWorkflowExecutionFailed

	SubscriptionGateUngated = ""

	SubscriptionGateEvidenceDigest    = notificationNameEvidenceDigest
	SubscriptionGateTaskAvailable     = notificationNameTaskAvailable
	SubscriptionGateTaskDailyDigest   = notificationNameTaskDailyDigest
	SubscriptionGateRiskNotifications = notificationNameRiskNotifications

	SubscriptionGateEvidenceDigestWire    = "evidenceDigest"
	SubscriptionGateTaskAvailableWire     = "taskAvailable"
	SubscriptionGateTaskDailyDigestWire   = "taskDailyDigest"
	SubscriptionGateRiskNotificationsWire = "riskNotifications"

	subscriptionGateEvidenceDigestWireNormalized    = "evidencedigest"
	subscriptionGateTaskAvailableWireNormalized     = "taskavailable"
	subscriptionGateTaskDailyDigestWireNormalized   = "taskdailydigest"
	subscriptionGateRiskNotificationsWireNormalized = "risknotifications"

	systemNotificationWorkflowExecutionFailedWireNormalized = "workflowexecutionfailed"
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

var systemNotificationInputAliases = map[string]string{
	SubscriptionGateEvidenceDigest:                          SystemNotificationNameEvidenceDigest,
	SubscriptionGateTaskAvailable:                           SystemNotificationNameTaskAvailable,
	SubscriptionGateTaskDailyDigest:                         SystemNotificationNameTaskDailyDigest,
	SubscriptionGateRiskNotifications:                       SystemNotificationNameRiskNotifications,
	notificationNameWorkflowExecutionFailed:                 SystemNotificationNameWorkflowExecutionFailed,
	subscriptionGateEvidenceDigestWireNormalized:            SystemNotificationNameEvidenceDigest,
	subscriptionGateTaskAvailableWireNormalized:             SystemNotificationNameTaskAvailable,
	subscriptionGateTaskDailyDigestWireNormalized:           SystemNotificationNameTaskDailyDigest,
	subscriptionGateRiskNotificationsWireNormalized:         SystemNotificationNameRiskNotifications,
	systemNotificationWorkflowExecutionFailedWireNormalized: SystemNotificationNameWorkflowExecutionFailed,
}

var systemNotificationNames = []string{
	SystemNotificationNameEvidenceDigest,
	SystemNotificationNameWorkflowExecutionFailed,
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

// NormalizeSystemNotificationName canonicalizes a system notification name and verifies support.
func NormalizeSystemNotificationName(notificationName string) (string, bool) {
	normalized := normalizeToken(notificationName)
	if normalized == "" {
		return "", false
	}

	canonical, ok := systemNotificationInputAliases[normalized]
	if !ok {
		return "", false
	}

	return canonical, true
}

func SystemNotificationNames() []string {
	return append([]string(nil), systemNotificationNames...)
}
