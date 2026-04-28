package notification_test

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGORMSystemDestinationRepositoryListTargetsBySubscriptionGateExpandsTargets(t *testing.T) {
	db := newNotificationSystemDestinationTestDB(t)

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				"channel":     " C-DIGEST ",
				"target_type": " channel ",
			},
		}),
	}).Error)

	repo := notification.NewGORMSystemDestinationRepository(db, notificationproviders.NewLookup())
	targets, err := repo.ListTargetsBySubscriptionGate(context.Background(), notification.SubscriptionGateEvidenceDigest)
	require.NoError(t, err)
	require.Len(t, targets, 1)

	assert.Equal(t, notification.DeliveryChannelSlack, targets[0].Provider)
	assert.Equal(t, "C-DIGEST", targets[0].Address["channel"])
	assert.Equal(t, "channel", targets[0].Address["target_type"])
}

func TestGORMSystemDestinationRepositoryListTargetsBySubscriptionGateExpandsMultipleRowsForSameProvider(t *testing.T) {
	db := newNotificationSystemDestinationTestDB(t)

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				"channel":     "C-PRIMARY",
				"target_type": "channel",
			},
		}),
	}).Error)
	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				"channel":     "C-SECONDARY",
				"target_type": "channel",
			},
		}),
	}).Error)

	repo := notification.NewGORMSystemDestinationRepository(db, notificationproviders.NewLookup())
	targets, err := repo.ListTargetsBySubscriptionGate(context.Background(), notification.SubscriptionGateEvidenceDigest)
	require.NoError(t, err)
	require.Len(t, targets, 2)

	channels := []string{targets[0].Address["channel"], targets[1].Address["channel"]}
	assert.ElementsMatch(t, []string{"C-PRIMARY", "C-SECONDARY"}, channels)
}

func TestGORMSystemDestinationRepositoryListTargetsBySubscriptionGateDeduplicatesTargets(t *testing.T) {
	db := newNotificationSystemDestinationTestDB(t)

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				"channel":     "C-DIGEST",
				"target_type": "channel",
			},
		}),
	}).Error)
	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				"channel":     "C-DIGEST",
				"target_type": "channel",
			},
		}),
	}).Error)

	repo := notification.NewGORMSystemDestinationRepository(db, notificationproviders.NewLookup())
	targets, err := repo.ListTargetsBySubscriptionGate(context.Background(), notification.SubscriptionGateEvidenceDigest)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "C-DIGEST", targets[0].Address["channel"])
}

func TestGORMSystemDestinationRepositoryListTargetsBySubscriptionGateRejectsInvalidTargets(t *testing.T) {
	db := newNotificationSystemDestinationTestDB(t)

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				"channel": "C-DIGEST",
			},
		}),
	}).Error)

	repo := notification.NewGORMSystemDestinationRepository(db, notificationproviders.NewLookup())
	_, err := repo.ListTargetsBySubscriptionGate(context.Background(), notification.SubscriptionGateEvidenceDigest)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid system notification destination")
}

func newNotificationSystemDestinationTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	return db
}
