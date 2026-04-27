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

	NotificationKindEvidenceDigest               Kind = "evidence_digest"
	NotificationKindWorkflowTaskAssigned         Kind = "workflow_task_assigned"
	NotificationKindWorkflowTaskDueSoon          Kind = "workflow_task_due_soon"
	NotificationKindWorkflowTaskDigest           Kind = "workflow_task_digest"
	NotificationKindWorkflowExecutionFailed      Kind = "workflow_execution_failed"
	NotificationKindRiskReviewDueReminder        Kind = "risk_review_due_reminder"
	NotificationKindRiskReviewOverdueEscalation  Kind = "risk_review_overdue_escalation"
	NotificationKindRiskStaleOpenReminder        Kind = "risk_stale_open_reminder"
	NotificationKindRiskOpenDigest               Kind = "risk_open_digest"
	NotificationKindPoamDeadlineReminder         Kind = "poam_deadline_reminder"
	NotificationKindPoamMilestoneOverdueReminder Kind = "poam_milestone_overdue_reminder"
	NotificationKindPoamOverdueNotification      Kind = "poam_overdue_notification"
	NotificationKindPoamOpenDigest               Kind = "poam_open_digest"
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

var notificationKindInputAliases = map[string]Kind{
	string(NotificationKindEvidenceDigest):               NotificationKindEvidenceDigest,
	string(NotificationKindWorkflowTaskAssigned):         NotificationKindWorkflowTaskAssigned,
	string(NotificationKindWorkflowTaskDueSoon):          NotificationKindWorkflowTaskDueSoon,
	string(NotificationKindWorkflowTaskDigest):           NotificationKindWorkflowTaskDigest,
	string(NotificationKindWorkflowExecutionFailed):      NotificationKindWorkflowExecutionFailed,
	string(NotificationKindRiskReviewDueReminder):        NotificationKindRiskReviewDueReminder,
	string(NotificationKindRiskReviewOverdueEscalation):  NotificationKindRiskReviewOverdueEscalation,
	string(NotificationKindRiskStaleOpenReminder):        NotificationKindRiskStaleOpenReminder,
	string(NotificationKindRiskOpenDigest):               NotificationKindRiskOpenDigest,
	string(NotificationKindPoamDeadlineReminder):         NotificationKindPoamDeadlineReminder,
	string(NotificationKindPoamMilestoneOverdueReminder): NotificationKindPoamMilestoneOverdueReminder,
	string(NotificationKindPoamOverdueNotification):      NotificationKindPoamOverdueNotification,
	string(NotificationKindPoamOpenDigest):               NotificationKindPoamOpenDigest,
}

var systemNotificationKinds = []Kind{
	NotificationKindEvidenceDigest,
	NotificationKindWorkflowExecutionFailed,
}

var systemNotificationKindSet = map[Kind]struct{}{
	NotificationKindEvidenceDigest:          {},
	NotificationKindWorkflowExecutionFailed: {},
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeSubscriptionGate canonicalizes a subscription gate and verifies support.
func NormalizeSubscriptionGate(gate string) (string, bool) {
	normalized := normalizeToken(gate)
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
func WireSubscriptionGate(gate string) (string, bool) {
	canonical, ok := NormalizeSubscriptionGate(gate)
	if !ok {
		return "", false
	}

	wireValue, ok := subscriptionGateWireValues[canonical]
	if !ok {
		return "", false
	}

	return wireValue, true
}

// NormalizeNotificationKind canonicalizes a true emitted notification kind.
func NormalizeNotificationKind(kind string) (Kind, bool) {
	normalized := normalizeToken(kind)
	if normalized == "" {
		return "", false
	}

	canonical, ok := notificationKindInputAliases[normalized]
	if !ok {
		return "", false
	}

	return canonical, true
}

// NormalizeSystemNotificationKind canonicalizes a kind and ensures it is eligible for system destinations.
func NormalizeSystemNotificationKind(kind string) (Kind, bool) {
	canonical, ok := NormalizeNotificationKind(kind)
	if !ok {
		return "", false
	}

	if _, exists := systemNotificationKindSet[canonical]; !exists {
		return "", false
	}

	return canonical, true
}

func SystemNotificationKinds() []string {
	result := make([]string, 0, len(systemNotificationKinds))
	for _, kind := range systemNotificationKinds {
		result = append(result, string(kind))
	}

	return result
}
