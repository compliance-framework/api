package relational

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	UUIDModel

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `json:"deletedAt" gorm:"index"` // Soft delete

	Email        string `json:"email" gorm:"uniqueIndex:idx_ccf_users_email,WHERE:deleted_at IS NULL;not null"`
	PasswordHash string `gorm:"" json:"-"`

	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`

	LastLogin    *time.Time `json:"lastLogin,omitempty"`
	IsActive     bool       `json:"isActive" gorm:"default:true"`
	IsLocked     bool       `json:"isLocked" gorm:"default:false"`
	FailedLogins int        `json:"failedLogins" gorm:"default:0"`

	AuthMethod     string `json:"authMethod"`
	UserAttributes string `json:"userAttributes"`

	// TaskDailyDigestSubscribed indicates if the user wants to receive a daily task digest email
	TaskDailyDigestSubscribed bool `json:"taskDailyDigestSubscribed" gorm:"default:false"`

	// RiskNotificationsSubscribed indicates if the user wants to receive risk lifecycle notifications.
	// The DB default is intentionally true so existing users are opted in when the column is introduced.
	RiskNotificationsSubscribed bool `json:"riskNotificationsSubscribed" gorm:"default:true"`
}

func (User) TableName() string {
	return "ccf_users"
}

func (u *User) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.PasswordHash = string(hash)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password))
	return err == nil
}
