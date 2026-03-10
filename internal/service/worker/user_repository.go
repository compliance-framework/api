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
			return NotificationUser{}, fmt.Errorf("user %s not found", userID)
		}
		return NotificationUser{}, fmt.Errorf("failed to fetch user %s: %w", userID, err)
	}

	return NotificationUser{
		ID:                           user.ID.String(),
		Email:                        user.Email,
		FirstName:                    user.FirstName,
		LastName:                     user.LastName,
		TaskAvailableEmailSubscribed: user.TaskAvailableEmailSubscribed,
		TaskDailyDigestSubscribed:    user.TaskDailyDigestSubscribed,
		RiskNotificationsSubscribed:  user.RiskNotificationsSubscribed,
	}, nil
}
