package notification

import (
	"context"
	"testing"

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
		NotificationType: string(NotificationKindEvidenceDigest),
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

func TestGORMConfiguredDestinationResolverResolveConfiguredDestinationNotFound(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	resolver := NewGORMConfiguredDestinationResolver(db)
	_, err = resolver.ResolveConfiguredDestination(context.Background(), testDigestDestinationKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfiguredDestinationNotFound)
}
