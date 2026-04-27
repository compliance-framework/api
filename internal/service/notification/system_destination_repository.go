package notification

import (
	"context"
	"fmt"

	"github.com/compliance-framework/api/internal/service/relational"
	"gorm.io/gorm"
)

type SystemDestinationRepository interface {
	ListTargetsByNotificationType(ctx context.Context, notificationType string) ([]Target, error)
}

type GORMSystemDestinationRepository struct {
	db        *gorm.DB
	providers ProviderLookup
}

func NewGORMSystemDestinationRepository(db *gorm.DB, providers ProviderLookup) *GORMSystemDestinationRepository {
	return &GORMSystemDestinationRepository{
		db:        db,
		providers: providers,
	}
}

func (r *GORMSystemDestinationRepository) ListTargetsByNotificationType(ctx context.Context, notificationType string) ([]Target, error) {
	if r == nil || r.db == nil || r.providers == nil {
		return nil, fmt.Errorf("system notification destination repository is not configured")
	}

	canonicalKind, ok := NormalizeSystemNotificationKind(notificationType)
	if !ok {
		return []Target{}, nil
	}

	var records []relational.SystemNotificationDestination
	if err := r.db.WithContext(ctx).
		Where("notification_type = ?", string(canonicalKind)).
		Find(&records).Error; err != nil {
		return nil, fmt.Errorf("failed to fetch system notification destinations for kind %s: %w", canonicalKind, err)
	}

	targets := make([]Target, 0, len(records))
	seen := make(map[string]struct{}, len(records))

	for i := range records {
		record := records[i]
		recordID := ""
		if record.ID != nil {
			recordID = record.ID.String()
		}

		provider, ok := NormalizeDeliveryChannel(record.Provider)
		if !ok {
			return nil, fmt.Errorf(
				"system notification destination %s has unsupported provider %q",
				recordID,
				record.Provider,
			)
		}

		configurator, ok := LookupTargetConfigurator(r.providers, provider)
		if !ok {
			return nil, fmt.Errorf(
				"system notification destination %s has unsupported provider %q",
				recordID,
				record.Provider,
			)
		}

		target, err := configurator.NormalizeTarget(Target{
			Provider: provider,
			Address:  record.Target.Data().Address,
		})
		if err != nil {
			return nil, fmt.Errorf(
				"invalid system notification destination %s for kind %s provider %s: %w",
				recordID,
				canonicalKind,
				provider,
				err,
			)
		}
		if err := target.Validate(); err != nil {
			return nil, fmt.Errorf(
				"invalid system notification destination %s for kind %s provider %s: %w",
				recordID,
				canonicalKind,
				provider,
				err,
			)
		}

		key := target.dedupKey()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, target)
	}

	return targets, nil
}
