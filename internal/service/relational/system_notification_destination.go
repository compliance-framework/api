package relational

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// SystemNotificationTarget stores the provider-specific address attributes for
// a system-wide notification destination target.
type SystemNotificationTarget struct {
	Address map[string]string `json:"address"`
}

// SystemNotificationDestination stores system-wide notification delivery
// targets for a notification type and provider combination.
type SystemNotificationDestination struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	NotificationType string `json:"notificationType" gorm:"not null;index:idx_ccf_system_notification_destinations_notification_type,WHERE:deleted_at IS NULL;index:idx_ccf_system_notification_destinations_type_provider,priority:1,WHERE:deleted_at IS NULL"`
	Provider         string `json:"provider" gorm:"not null;index:idx_ccf_system_notification_destinations_type_provider,priority:2,WHERE:deleted_at IS NULL"`

	Target datatypes.JSONType[SystemNotificationTarget] `json:"target"`
}

func (SystemNotificationDestination) TableName() string {
	return "ccf_system_notification_destinations"
}
