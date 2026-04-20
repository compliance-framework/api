package worker

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

func TestGORMUserRepositoryFindUserByIDDoesNotRequireSlackLink(t *testing.T) {
	db := newWorkerUserRepositoryTestDB(t)
	userID := uuid.New()

	require.NoError(t, db.Create(&relational.User{
		UUIDModel:  relational.UUIDModel{ID: &userID},
		Email:      "alice@example.com",
		FirstName:  "Alice",
		LastName:   "Tester",
		IsActive:   true,
		AuthMethod: "password",
	}).Error)
	require.NoError(t, db.Create(&relational.UserNotificationSubscription{
		UserID:           userID.String(),
		NotificationType: "task_daily_digest",
		Channels:         datatypes.JSONSlice[string]{"email", "slack"},
	}).Error)

	repo := NewGORMUserRepository(db)
	user, err := repo.FindUserByID(context.Background(), userID.String())
	require.NoError(t, err)
	assert.Equal(t, userID.String(), user.ID)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Empty(t, user.SlackUserID)
	assert.Len(t, user.NotificationSubscriptions, 1)
}

func TestGORMUserRepositoryFindUserByIDIncludesSlackLinkWhenPresent(t *testing.T) {
	db := newWorkerUserRepositoryTestDB(t)
	userID := uuid.New()

	require.NoError(t, db.Create(&relational.User{
		UUIDModel:  relational.UUIDModel{ID: &userID},
		Email:      "alice@example.com",
		FirstName:  "Alice",
		LastName:   "Tester",
		IsActive:   true,
		AuthMethod: "password",
	}).Error)
	require.NoError(t, db.Create(&relational.SlackUserLink{
		UserID:      userID.String(),
		SlackUserID: "UALICE",
		SlackTeamID: "T123",
	}).Error)

	repo := NewGORMUserRepository(db)
	user, err := repo.FindUserByID(context.Background(), userID.String())
	require.NoError(t, err)
	assert.Equal(t, "UALICE", user.SlackUserID)
}

func newWorkerUserRepositoryTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.User{},
		&relational.SlackUserLink{},
		&relational.UserNotificationSubscription{},
	))

	return db
}
