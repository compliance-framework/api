package worker

import (
	"context"
	"errors"
	"fmt"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GORMUserRepository implements UserRepository using GORM
type GORMUserRepository struct {
	db *gorm.DB
}

// NewGORMUserRepository creates a new GORMUserRepository
func NewGORMUserRepository(db *gorm.DB) *GORMUserRepository {
	return &GORMUserRepository{db: db}
}

// FindUserByID looks up a user by UUID string and returns a NotificationUser
func (r *GORMUserRepository) FindUserByID(ctx context.Context, userID string) (NotificationUser, error) {
	parsed, err := uuid.Parse(userID)
	if err != nil {
		return NotificationUser{}, fmt.Errorf("invalid user ID %q: %w", userID, err)
	}

	var user relational.User
	if err := r.db.WithContext(ctx).First(&user, parsed).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return NotificationUser{}, fmt.Errorf("user %s not found: %w", userID, gorm.ErrRecordNotFound)
		}
		return NotificationUser{}, fmt.Errorf("failed to fetch user %s: %w", userID, err)
	}

	var rows []relational.UserNotificationSubscription
	err = r.db.WithContext(ctx).
		Where("user_id = ?", user.ID.String()).
		Find(&rows).Error
	if err != nil {
		return NotificationUser{}, fmt.Errorf("failed to fetch notification subscriptions for user %s: %w", userID, err)
	}

	var slackLink relational.SlackUserLink
	var slackUserID string
	err = r.db.WithContext(ctx).
		Where("user_id = ?", user.ID.String()).
		First(&slackLink).Error
	if err == nil {
		slackUserID = slackLink.SlackUserID
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return NotificationUser{}, fmt.Errorf("failed to fetch slack user link for user %s: %w", userID, err)
	}

	subscriptions := make([]NotificationSubscription, 0, len(rows))
	for i := range rows {
		channels := make([]string, len(rows[i].Channels))
		copy(channels, rows[i].Channels)

		subscriptions = append(subscriptions, NotificationSubscription{
			NotificationType: rows[i].NotificationType,
			Channels:         channels,
		})
	}

	return NotificationUser{
		ID:                        user.ID.String(),
		Email:                     user.Email,
		FirstName:                 user.FirstName,
		LastName:                  user.LastName,
		SlackUserID:               slackUserID,
		NotificationSubscriptions: subscriptions,
	}, nil
}
