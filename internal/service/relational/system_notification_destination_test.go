package relational

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestSystemNotificationDestinationAutoMigrateCreatesNotificationIndexes(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(&SystemNotificationDestination{}))

	assert.True(
		t,
		db.Migrator().HasIndex(&SystemNotificationDestination{}, "idx_ccf_system_notification_destinations_notification_type"),
	)
	assert.True(
		t,
		db.Migrator().HasIndex(&SystemNotificationDestination{}, "idx_ccf_system_notification_destinations_type_provider"),
	)
}
