package notification

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	testDigestDestinationKey = "slack.digest_channel"
	testAddressKeyChannel    = "channel"
	testAddressKeyTargetType = "target_type"
	testSlackTargetChannel   = "channel"
)

func TestGORMConfiguredDestinationResolverResolveConfiguredDestination(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	record := relational.SystemNotificationDestination{
		NotificationType: NotificationTypeEvidenceDigest,
		Provider:         DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				testAddressKeyChannel:    "ccf-alerts",
				testAddressKeyTargetType: testSlackTargetChannel,
			},
		}),
	}
	require.NoError(t, db.Create(&record).Error)

	resolver := NewGORMConfiguredDestinationResolver(db)
	destination, err := resolver.ResolveConfiguredDestination(context.Background(), testDigestDestinationKey)
	require.NoError(t, err)

	assert.Equal(t, DeliveryChannelSlack, destination.Provider)
	assert.Equal(t, "ccf-alerts", destination.Address[testAddressKeyChannel])
	assert.Equal(t, testSlackTargetChannel, destination.Address[testAddressKeyTargetType])
}

func TestGORMConfiguredDestinationResolverResolveConfiguredDestinationUsesNewestMatchingRecord(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	older := time.Date(2026, 4, 26, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 4, 27, 9, 0, 0, 0, time.UTC)

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		CreatedAt:        older,
		UpdatedAt:        older,
		NotificationType: NotificationTypeEvidenceDigest,
		Provider:         DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				testAddressKeyChannel:    "old-alerts",
				testAddressKeyTargetType: testSlackTargetChannel,
			},
		}),
	}).Error)
	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		CreatedAt:        newer,
		UpdatedAt:        newer,
		NotificationType: NotificationTypeEvidenceDigest,
		Provider:         DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				testAddressKeyChannel:    "new-alerts",
				testAddressKeyTargetType: testSlackTargetChannel,
			},
		}),
	}).Error)

	resolver := NewGORMConfiguredDestinationResolver(db)
	destination, err := resolver.ResolveConfiguredDestination(context.Background(), testDigestDestinationKey)
	require.NoError(t, err)

	assert.Equal(t, "new-alerts", destination.Address[testAddressKeyChannel])
}

func TestGORMConfiguredDestinationResolverResolveConfiguredDestinationNotFound(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	resolver := NewGORMConfiguredDestinationResolver(db)
	_, err = resolver.ResolveConfiguredDestination(context.Background(), testDigestDestinationKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfiguredDestinationNotFound)
}
