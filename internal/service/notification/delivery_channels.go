package notification

import "sort"

const (
	DeliveryChannelEmail = "email"
	DeliveryChannelSlack = "slack"
)

var supportedDeliveryChannels = map[string]struct{}{
	DeliveryChannelEmail: {},
	DeliveryChannelSlack: {},
}

// NormalizeDeliveryChannel canonicalizes a channel name and verifies support.
func NormalizeDeliveryChannel(channel string) (string, bool) {
	normalized := normalizeToken(channel)
	if normalized == "" {
		return "", false
	}

	if _, ok := supportedDeliveryChannels[normalized]; !ok {
		return "", false
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
