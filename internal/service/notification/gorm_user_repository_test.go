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
		NotificationType: SubscriptionGateEvidenceDigest,
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

func TestGORMUserRepositoryListActiveUsersBySubscriptionGateIncludesSlackIdentity(t *testing.T) {
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
		NotificationType: SubscriptionGateTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{DeliveryChannelSlack},
	}).Error)
	require.NoError(t, db.Create(&relational.SlackUserLink{
		UserID:      userID.String(),
		SlackUserID: "UWORKFLOW",
		SlackTeamID: "T123",
	}).Error)

	repo := NewGORMUserRepository(db)
	users, err := repo.ListActiveUsersBySubscriptionGate(context.Background(), SubscriptionGateTaskDailyDigest)
	require.NoError(t, err)
	require.Len(t, users, 1)

	identity, ok := users[0].Identities[DeliveryChannelSlack]
	require.True(t, ok)
	assert.Equal(t, "UWORKFLOW", identity["channel"])
	assert.Equal(t, "direct_message", identity["target_type"])
}

func TestGORMUserRepositoryListActiveUserIDsBySubscriptionGate(t *testing.T) {
	db := newNotificationTestDB(t)
	activeID := uuid.New()
	inactiveID := uuid.New()
	lockedID := uuid.New()
	invalidChannelID := uuid.New()

	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          activeID,
		"email":       "active@example.com",
		"is_active":   true,
		"is_locked":   false,
		"auth_method": "password",
	}).Error)
	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          inactiveID,
		"email":       "inactive@example.com",
		"is_active":   false,
		"is_locked":   false,
		"auth_method": "password",
	}).Error)
	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          lockedID,
		"email":       "locked@example.com",
		"is_active":   true,
		"is_locked":   true,
		"auth_method": "password",
	}).Error)
	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          invalidChannelID,
		"email":       "invalid@example.com",
		"is_active":   true,
		"is_locked":   false,
		"auth_method": "password",
	}).Error)

	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           activeID.String(),
		NotificationType: SubscriptionGateTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{DeliveryChannelEmail},
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           inactiveID.String(),
		NotificationType: SubscriptionGateTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{DeliveryChannelEmail},
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           lockedID.String(),
		NotificationType: SubscriptionGateTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{DeliveryChannelSlack},
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           invalidChannelID.String(),
		NotificationType: SubscriptionGateTaskDailyDigest,
		Channels:         datatypes.JSONSlice[string]{"invalid-channel"},
	}).Error)

	repo := NewGORMUserRepository(db)
	userIDs, err := repo.ListActiveUserIDsBySubscriptionGate(context.Background(), SubscriptionGateTaskDailyDigest)
	require.NoError(t, err)
	require.Len(t, userIDs, 1)
	assert.Equal(t, activeID.String(), userIDs[0])
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
