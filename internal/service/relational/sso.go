package relational

import (
	"time"

	"gorm.io/gorm"
)

type SSOUserLink struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"`

	UserID     string    `json:"userId" gorm:"not null;index"`
	Provider   string    `json:"provider" gorm:"not null;index"`
	ExternalID string    `json:"externalId" gorm:"not null"`
	Email      string    `json:"email"`
	Groups     string    `json:"groups"`
	LastSync   time.Time `json:"lastSync"`

	User User `json:"user,omitempty" gorm:"foreignKey:UserID;references:ID"`
}

func (SSOUserLink) TableName() string {
	return "ccf_sso_user_links"
}

// TODO: Database SSOProvider model (future) - eventually move provider config from YAML to database
