package notification

import (
	"sort"
	"strings"
)

const (
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

	DeliveryChannelEmail = "email"
	DeliveryChannelSlack = "slack"

	SlackTargetChannel       = "channel"
	SlackTargetDirectMessage = "direct_message"
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

// NormalizeDeliveryChannel canonicalizes a channel name and verifies support.
func NormalizeDeliveryChannel(channel string) (string, bool) {
	normalized := normalizeToken(channel)
	if normalized == "" {
		return "", false
	}

	for _, r := range normalized {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return "", false
		}
	}

	return normalized, true
}

// NormalizeDeliveryChannels canonicalizes channels and returns unsupported values separately.
func NormalizeDeliveryChannels(channels []string) (normalized []string, invalid []string) {
	if len(channels) == 0 {
		return []string{}, []string{}
	}

	seen := make(map[string]struct{}, len(channels))
	invalidSeen := make(map[string]struct{}, len(channels))

	normalized = make([]string, 0, len(channels))
	invalid = make([]string, 0)

	for _, channel := range channels {
		canonical, ok := NormalizeDeliveryChannel(channel)
		if !ok {
			trimmed := normalizeToken(channel)
			if _, exists := invalidSeen[trimmed]; !exists {
				invalidSeen[trimmed] = struct{}{}
				invalid = append(invalid, trimmed)
			}
			continue
		}

		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}

	sort.Strings(normalized)
	sort.Strings(invalid)

	return normalized, invalid
}

func NormalizeSlackTarget(target string) (string, bool) {
	switch normalizeToken(target) {
	case SlackTargetChannel:
		return SlackTargetChannel, true
	case SlackTargetDirectMessage, "directmessage", "dm":
		return SlackTargetDirectMessage, true
	default:
		return "", false
	}
}
