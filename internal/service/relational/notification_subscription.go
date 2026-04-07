package relational

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// UserNotificationSubscription stores selected delivery channels for a user notification type.
type UserNotificationSubscription struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	UserID string `json:"userId" gorm:"not null;uniqueIndex:idx_ccf_user_notification_subscriptions_unique,WHERE:deleted_at IS NULL"`

	NotificationType string                      `json:"notificationType" gorm:"not null;uniqueIndex:idx_ccf_user_notification_subscriptions_unique,WHERE:deleted_at IS NULL;index:idx_ccf_user_notification_subscriptions_notification_type,WHERE:deleted_at IS NULL"`
	Channels         datatypes.JSONSlice[string] `json:"channels"`
}

func (UserNotificationSubscription) TableName() string {
	return "ccf_user_notification_subscriptions"
}
