package service

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
