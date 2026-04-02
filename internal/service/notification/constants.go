package notification

import (
	"sort"
	"strings"
)

const (
	NotificationTypeEvidenceDigest = "evidence_digest"
	NotificationTypeTaskAvailable  = "task_available"

	NotificationTypeEvidenceDigestWire = "evidenceDigest"
	NotificationTypeTaskAvailableWire  = "taskAvailable"

	notificationTypeEvidenceDigestWireNormalized = "evidencedigest"
	notificationTypeTaskAvailableWireNormalized  = "taskavailable"

	DeliveryChannelEmail = "email"
	DeliveryChannelSlack = "slack"
)

var notificationTypeInputAliases = map[string]string{
	NotificationTypeEvidenceDigest:               NotificationTypeEvidenceDigest,
	NotificationTypeTaskAvailable:                NotificationTypeTaskAvailable,
	notificationTypeEvidenceDigestWireNormalized: NotificationTypeEvidenceDigest,
	notificationTypeTaskAvailableWireNormalized:  NotificationTypeTaskAvailable,
}

var notificationTypeWireValues = map[string]string{
	NotificationTypeEvidenceDigest: NotificationTypeEvidenceDigestWire,
	NotificationTypeTaskAvailable:  NotificationTypeTaskAvailableWire,
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

	switch normalized {
	case DeliveryChannelEmail, DeliveryChannelSlack:
		return normalized, true
	default:
		return "", false
	}
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
