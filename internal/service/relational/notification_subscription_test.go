package relational

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestUserNotificationSubscriptionAutoMigrateCreatesNotificationTypeIndex(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&UserNotificationSubscription{}))

	assert.True(
		t,
		db.Migrator().HasIndex(&UserNotificationSubscription{}, "idx_ccf_user_notification_subscriptions_notification_type"),
	)
}
