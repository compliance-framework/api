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

	Email        string `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null" json:"-"`

	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`

	LastLogin    *time.Time `json:"lastLogin,omitempty"`
	IsActive     bool       `json:"isActive" gorm:"default:true"`
	IsLocked     bool       `json:"isLocked" gorm:"default:false"`
	FailedLogins int        `json:"failedLogins" gorm:"default:0"`

	ResetToken       *string `json:"-"`
	ResetTokenExpiry *time.Time
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
