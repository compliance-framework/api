package notification

import (
	"strings"
)

const (
	NotificationTypeUngated = ""

	NotificationTypeEvidenceDigest    = "evidence_digest"
	NotificationTypeTaskAvailable     = "task_available"
	NotificationTypeTaskDailyDigest   = "task_daily_digest"
	NotificationTypeRiskNotifications = "risk_notifications"

	NotificationTypeEvidenceDigestWire    = "evidenceDigest"
	NotificationTypeTaskAvailableWire     = "taskAvailable"
	NotificationTypeTaskDailyDigestWire   = "taskDailyDigest"
	NotificationTypeRiskNotificationsWire = "riskNotifications"

	notificationTypeEvidenceDigestWireNormalized    = "evidencedigest"
	notificationTypeTaskAvailableWireNormalized     = "taskavailable"
	notificationTypeTaskDailyDigestWireNormalized   = "taskdailydigest"
	notificationTypeRiskNotificationsWireNormalized = "risknotifications"
)

var notificationTypeInputAliases = map[string]string{
	NotificationTypeEvidenceDigest:                  NotificationTypeEvidenceDigest,
	NotificationTypeTaskAvailable:                   NotificationTypeTaskAvailable,
	NotificationTypeTaskDailyDigest:                 NotificationTypeTaskDailyDigest,
	NotificationTypeRiskNotifications:               NotificationTypeRiskNotifications,
	notificationTypeEvidenceDigestWireNormalized:    NotificationTypeEvidenceDigest,
	notificationTypeTaskAvailableWireNormalized:     NotificationTypeTaskAvailable,
	notificationTypeTaskDailyDigestWireNormalized:   NotificationTypeTaskDailyDigest,
	notificationTypeRiskNotificationsWireNormalized: NotificationTypeRiskNotifications,
}

var notificationTypeWireValues = map[string]string{
	NotificationTypeEvidenceDigest:    NotificationTypeEvidenceDigestWire,
	NotificationTypeTaskAvailable:     NotificationTypeTaskAvailableWire,
	NotificationTypeTaskDailyDigest:   NotificationTypeTaskDailyDigestWire,
	NotificationTypeRiskNotifications: NotificationTypeRiskNotificationsWire,
}

var systemNotificationTypes = []string{
	NotificationTypeEvidenceDigest,
}

func normalizeToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeNotificationType canonicalizes a notification type and verifies support.
func NormalizeNotificationType(notificationType string) (string, bool) {
	normalized := normalizeToken(notificationType)
	if normalized == "" {
		return "", false
	}

	canonical, ok := notificationTypeInputAliases[normalized]
	if !ok {
		return "", false
	}

	return canonical, true
}

// WireNotificationType returns camelCase for a supported notification type.
func WireNotificationType(notificationType string) (string, bool) {
	canonical, ok := NormalizeNotificationType(notificationType)
	if !ok {
		return "", false
	}

	wireValue, ok := notificationTypeWireValues[canonical]
	if !ok {
		return "", false
	}

	return wireValue, true
}

func SystemNotificationTypes() []string {
	return append([]string(nil), systemNotificationTypes...)
}
