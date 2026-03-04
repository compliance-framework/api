package relational

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type CcfPoamItem struct {
	ID               uuid.UUID  `gorm:"type:uuid;primaryKey"`
	SspID            uuid.UUID  `gorm:"type:uuid;index;not null"`
	Title            string     `gorm:"not null"`
	Description      string     `gorm:"not null"`
	Status           string     `gorm:"type:text;index;not null;check:poam_items_status IN ('open','in-progress','completed','overdue')"`
	Deadline         *time.Time `gorm:"index"`
	ResourceRequired *string
	PocName          *string
	PocEmail         *string
	PocPhone         *string
	Remarks          *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Milestones       []CcfPoamItemMilestone `gorm:"constraint:OnDelete:CASCADE"`
}

type CcfPoamItemMilestone struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	PoamItemID  uuid.UUID `gorm:"type:uuid;index;not null"`
	Title       string    `gorm:"not null"`
	Description string    `gorm:"not null"`
	Status      string    `gorm:"type:text;not null;check:poam_item_milestone_status IN ('planned','completed')"`
	DueDate     *time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type CcfPoamItemRiskLink struct {
	PoamItemID uuid.UUID `gorm:"type:uuid;not null;index:poam_item_risk_links_unique,unique"`
	RiskID     uuid.UUID `gorm:"type:uuid;not null;index:poam_item_risk_links_unique,unique"`
}

func (l *CcfPoamItemRiskLink) TableName() string {
	return "poam_item_risk_links"
}

func (l *CcfPoamItemRiskLink) BeforeCreate(tx *gorm.DB) (err error) {
	return nil
}
