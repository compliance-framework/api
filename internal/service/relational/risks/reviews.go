package risks

import (
	"errors"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type RiskReview struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`

	RiskID              uuid.UUID         `json:"riskId" gorm:"type:uuid;not null;index"`
	ReviewedByUserID    *uuid.UUID        `json:"reviewedByUserId" gorm:"type:uuid;index"`
	ReviewedAt          time.Time         `json:"reviewedAt" gorm:"not null;index"`
	Decision            string            `json:"decision" gorm:"type:varchar(64);not null"`
	NextReviewDeadline  *time.Time        `json:"nextReviewDeadline"`
	ReviewJustification *string           `json:"reviewJustification" gorm:"type:text"`
	RiskSnapshot        datatypes.JSONMap `json:"riskSnapshot" gorm:"type:jsonb"`
}

func (RiskReview) TableName() string {
	return "risk_reviews"
}

func (r *RiskReview) BeforeCreate(_ *gorm.DB) error {
	if r.ID == nil {
		id := uuid.New()
		r.ID = &id
	}
	return nil
}

func (r *RiskReview) BeforeUpdate(_ *gorm.DB) error {
	return errors.New("risk reviews are append-only")
}

func (r *RiskReview) BeforeDelete(_ *gorm.DB) error {
	return errors.New("risk reviews are append-only")
}
