package notification

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestGORMUserRepositoryFindUserByIDIncludesSlackIdentity(t *testing.T) {
	db := newNotificationTestDB(t)
	userID := uuid.New()

	require.NoError(t, db.Create(&relational.User{
		UUIDModel: relational.UUIDModel{ID: &userID},
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Tester",
		IsActive:  true,
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           userID.String(),
		NotificationType: NotificationTypeEvidenceDigest,
		Channels:         datatypes.JSONSlice[string]{DeliveryChannelEmail, DeliveryChannelSlack},
	}).Error)
	require.NoError(t, db.Create(&relational.SlackUserLink{
		UserID:      userID.String(),
		SlackUserID: "UALICE",
		SlackTeamID: "T123",
	}).Error)

	repo := NewGORMUserRepository(db)
	user, err := repo.FindUserByID(context.Background(), userID.String())
	require.NoError(t, err)

	identity, ok := user.Identities[DeliveryChannelSlack]
	require.True(t, ok)
	assert.Equal(t, "UALICE", identity["channel"])
	assert.Equal(t, "direct_message", identity["target_type"])
}

func TestGORMUserRepositoryListActiveUsersByNotificationTypeIncludesSlackIdentity(t *testing.T) {
	db := newNotificationTestDB(t)
	userID := uuid.New()

	require.NoError(t, db.Create(&relational.User{
		UUIDModel: relational.UUIDModel{ID: &userID},
		Email:     "alice@example.com",
		FirstName: "Alice",
		IsActive:  true,
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           userID.String(),
		NotificationType: NotificationTypeTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{DeliveryChannelSlack},
	}).Error)
	require.NoError(t, db.Create(&relational.SlackUserLink{
		UserID:      userID.String(),
		SlackUserID: "UWORKFLOW",
		SlackTeamID: "T123",
	}).Error)

	repo := NewGORMUserRepository(db)
	users, err := repo.ListActiveUsersByNotificationType(context.Background(), NotificationTypeTaskDailyDigest)
	require.NoError(t, err)
	require.Len(t, users, 1)

	identity, ok := users[0].Identities[DeliveryChannelSlack]
	require.True(t, ok)
	assert.Equal(t, "UWORKFLOW", identity["channel"])
	assert.Equal(t, "direct_message", identity["target_type"])
}

func newNotificationTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.User{},
		&relational.UserNotificationSubscription{},
		&relational.SlackUserLink{},
	))

	return db
}
