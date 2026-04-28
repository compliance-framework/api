package notification

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/relational"
	"gorm.io/gorm"
)

const configuredDestinationKeySlackDigest = "slack.digest_channel"

type GORMConfiguredDestinationResolver struct {
	db *gorm.DB
}

func NewGORMConfiguredDestinationResolver(db *gorm.DB) *GORMConfiguredDestinationResolver {
	return &GORMConfiguredDestinationResolver{db: db}
}

func (r *GORMConfiguredDestinationResolver) ResolveConfiguredDestination(ctx context.Context, key string) (ConfiguredDestination, error) {
	trimmedKey := strings.TrimSpace(key)
	if trimmedKey == "" {
		return ConfiguredDestination{}, fmt.Errorf("%w: %q", ErrConfiguredDestinationNotFound, key)
	}
	if r == nil || r.db == nil {
		return ConfiguredDestination{}, fmt.Errorf("%w: %q", ErrConfiguredDestinationNotFound, key)
	}

	lookup, ok := configuredDestinationLookup(trimmedKey)
	if !ok {
		return ConfiguredDestination{}, fmt.Errorf("%w: %q", ErrConfiguredDestinationNotFound, key)
	}

	var record relational.SystemNotificationDestination
	result := r.db.WithContext(ctx).
		Where("notification_type = ? AND provider = ?", lookup.NotificationType, lookup.Provider).
		Order("updated_at DESC, created_at DESC, id DESC").
		Limit(1).
		Find(&record)
	if result.Error != nil {
		return ConfiguredDestination{}, fmt.Errorf("failed to fetch configured destination %q: %w", trimmedKey, result.Error)
	}
	if result.RowsAffected == 0 {
		return ConfiguredDestination{}, fmt.Errorf("%w: %q", ErrConfiguredDestinationNotFound, key)
	}

	provider, ok := NormalizeDeliveryChannel(record.Provider)
	if !ok {
		return ConfiguredDestination{}, fmt.Errorf("%w: configured destination %q uses unsupported provider %q", ErrUnsupportedChannel, trimmedKey, record.Provider)
	}

	target := record.Target.Data()
	address := make(map[string]string, len(target.Address))
	for rawKey, rawValue := range target.Address {
		address[strings.TrimSpace(rawKey)] = strings.TrimSpace(rawValue)
	}

	destination := ConfiguredDestination{
		Provider: provider,
		Address:  address,
	}
	if err := destination.Validate(); err != nil {
		return ConfiguredDestination{}, fmt.Errorf("configured destination %q is invalid: %w", trimmedKey, err)
	}

	return destination, nil
}

type configuredDestinationRecordLookup struct {
	NotificationType string
	Provider         string
}

func configuredDestinationLookup(key string) (configuredDestinationRecordLookup, bool) {
	switch strings.TrimSpace(key) {
	case configuredDestinationKeySlackDigest:
		return configuredDestinationRecordLookup{
			NotificationType: SubscriptionGateEvidenceDigest,
			Provider:         DeliveryChannelSlack,
		}, true
	default:
		return configuredDestinationRecordLookup{}, false
	}
}
