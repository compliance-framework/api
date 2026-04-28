package service

import (
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestBackfillLegacyNotificationSubscriptions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.UserNotificationSubscription{}))
	require.NoError(t, db.Exec(`ALTER TABLE ccf_users ADD COLUMN task_available_email_subscribed BOOLEAN`).Error)

	createUser := func(email string) relational.User {
		user := relational.User{
			Email:      email,
			FirstName:  "Test",
			LastName:   "User",
			AuthMethod: "password",
			IsActive:   true,
		}
		require.NoError(t, user.SetPassword("Pa55w0rd"))
		require.NoError(t, db.Create(&user).Error)
		return user
	}

	userWithLegacySubscription := createUser("legacy-1@example.com")
	userWithoutLegacySubscription := createUser("legacy-2@example.com")
	userWithExistingSubscription := createUser("legacy-3@example.com")

	require.NoError(t,
		db.Table("ccf_users").
			Where("id = ?", userWithLegacySubscription.ID.String()).
			Update("task_available_email_subscribed", true).
			Error,
	)
	require.NoError(t,
		db.Table("ccf_users").
			Where("id = ?", userWithExistingSubscription.ID.String()).
			Update("task_available_email_subscribed", true).
			Error,
	)

	existing := relational.UserNotificationSubscription{
		UserID:           userWithExistingSubscription.ID.String(),
		NotificationType: notification.NotificationTypeTaskAvailable,
		Channels:         []string{notification.DeliveryChannelEmail},
	}
	require.NoError(t, db.Create(&existing).Error)

	require.NoError(t,
		backfillLegacyNotificationSubscriptions(
			db,
			"task_available_email_subscribed",
			notification.NotificationTypeTaskAvailable,
			"task-available email",
		),
	)

	var rows []relational.UserNotificationSubscription
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 2)

	rowsByUserID := make(map[string]relational.UserNotificationSubscription, len(rows))
	for _, row := range rows {
		rowsByUserID[row.UserID] = row
	}

	assert.Equal(t, notification.NotificationTypeTaskAvailable, rowsByUserID[userWithLegacySubscription.ID.String()].NotificationType)
	assert.Equal(t, []string{notification.DeliveryChannelEmail}, []string(rowsByUserID[userWithLegacySubscription.ID.String()].Channels))

	assert.Equal(t, notification.NotificationTypeTaskAvailable, rowsByUserID[userWithExistingSubscription.ID.String()].NotificationType)
	assert.Equal(t, []string{notification.DeliveryChannelEmail}, []string(rowsByUserID[userWithExistingSubscription.ID.String()].Channels))

	require.NoError(t,
		backfillLegacyNotificationSubscriptions(
			db,
			"task_available_email_subscribed",
			notification.NotificationTypeTaskAvailable,
			"task-available email",
		),
	)

	var count int64
	require.NoError(t, db.Model(&relational.UserNotificationSubscription{}).Count(&count).Error)
	assert.Equal(t, int64(2), count)

	var noSubscriptionCount int64
	require.NoError(t,
		db.Model(&relational.UserNotificationSubscription{}).
			Where("user_id = ?", userWithoutLegacySubscription.ID.String()).
			Count(&noSubscriptionCount).
			Error,
	)
	assert.Zero(t, noSubscriptionCount)
}

func TestBackfillLegacyRiskNotificationSubscriptions(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.UserNotificationSubscription{}))
	require.NoError(t, db.Exec(`ALTER TABLE ccf_users ADD COLUMN risk_notifications_subscribed BOOLEAN`).Error)

	user := relational.User{
		Email:      "legacy-risk@example.com",
		FirstName:  "Legacy",
		LastName:   "Risk",
		AuthMethod: "password",
		IsActive:   true,
	}
	require.NoError(t, user.SetPassword("Pa55w0rd"))
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t,
		db.Table("ccf_users").
			Where("id = ?", user.ID.String()).
			Update("risk_notifications_subscribed", true).
			Error,
	)

	require.NoError(t, migrateLegacyRiskNotificationSubscriptions(db))

	var rows []relational.UserNotificationSubscription
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	assert.Equal(t, notification.NotificationTypeRiskNotifications, rows[0].NotificationType)
	assert.Equal(t, []string{notification.DeliveryChannelEmail}, []string(rows[0].Channels))
	assert.Equal(t, user.ID.String(), rows[0].UserID)

	require.NoError(t, migrateLegacyRiskNotificationSubscriptions(db))

	var count int64
	require.NoError(t, db.Model(&relational.UserNotificationSubscription{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

func TestMigrateLegacySystemNotificationDestinationsBackfillsSlackDigestChannel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	cfg := &config.Config{
		Slack: &config.SlackConfig{
			DigestChannel: "ccf-alerts",
		},
	}

	require.NoError(t, migrateLegacySystemNotificationDestinations(db, cfg, true))

	var rows []relational.SystemNotificationDestination
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	assert.Equal(t, notification.NotificationTypeEvidenceDigest, rows[0].NotificationType)
	assert.Equal(t, notification.DeliveryChannelSlack, rows[0].Provider)
	target := rows[0].Target.Data()
	assert.Equal(t, "ccf-alerts", target.Address[slackprovider.AddressKeyChannel])
	assert.Equal(t, slackprovider.TargetTypeChannel, target.Address[slackprovider.AddressKeyTargetType])
}

func TestMigrateLegacySystemNotificationDestinationsDoesNotOverwriteExistingRow(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	existing := relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				slackprovider.AddressKeyChannel:    "existing-channel",
				slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
			},
		}),
	}
	require.NoError(t, db.Create(&existing).Error)

	cfg := &config.Config{
		Slack: &config.SlackConfig{
			DigestChannel: "env-channel",
		},
	}

	require.NoError(t, migrateLegacySystemNotificationDestinations(db, cfg, true))

	var rows []relational.SystemNotificationDestination
	require.NoError(t, db.Find(&rows).Error)
	require.Len(t, rows, 1)
	assert.Equal(t, "existing-channel", rows[0].Target.Data().Address[slackprovider.AddressKeyChannel])
}

func TestMigrateLegacySystemNotificationDestinationsSkipsWhenTableAlreadyExists(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	cfg := &config.Config{
		Slack: &config.SlackConfig{
			DigestChannel: "ccf-alerts",
		},
	}

	require.NoError(t, migrateLegacySystemNotificationDestinations(db, cfg, false))

	var count int64
	require.NoError(t, db.Model(&relational.SystemNotificationDestination{}).Count(&count).Error)
	assert.Zero(t, count)
}
