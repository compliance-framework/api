package risks

import (
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RiskStatus string

const (
	RiskStatusOpen                  RiskStatus = "open"
	RiskStatusInvestigating         RiskStatus = "investigating"
	RiskStatusMitigatingPlanned     RiskStatus = "mitigating-planned"
	RiskStatusMitigatingImplemented RiskStatus = "mitigating-implemented"
	RiskStatusRiskAccepted          RiskStatus = "risk-accepted"
	RiskStatusClosed                RiskStatus = "closed"
)

func (s RiskStatus) IsValid() bool {
	switch s {
	case RiskStatusOpen,
		RiskStatusInvestigating,
		RiskStatusMitigatingPlanned,
		RiskStatusMitigatingImplemented,
		RiskStatusRiskAccepted,
		RiskStatusClosed:
		return true
	default:
		return false
	}
}

type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

func (l RiskLevel) IsValid() bool {
	switch l {
	case RiskLevelLow, RiskLevelMedium, RiskLevelHigh:
		return true
	default:
		return false
	}
}

type RiskSourceType string

const (
	RiskSourceTypeManual       RiskSourceType = "manual"
	RiskSourceTypeEvidenceAuto RiskSourceType = "evidence-auto"
	RiskSourceTypeOscalImport  RiskSourceType = "oscal-import"
)

func (s RiskSourceType) IsValid() bool {
	switch s {
	case RiskSourceTypeManual, RiskSourceTypeEvidenceAuto, RiskSourceTypeOscalImport:
		return true
	default:
		return false
	}
}

type Risk struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	Title       string `json:"title" gorm:"not null"`
	Description string `json:"description" gorm:"not null"`
	Status      string `json:"status" gorm:"type:varchar(64);not null;index"`

	SSPID              uuid.UUID  `json:"sspId" gorm:"type:uuid;not null;index"`
	PrimaryOwnerUserID *uuid.UUID `json:"primaryOwnerUserId" gorm:"type:uuid;index"`
	Likelihood         *string    `json:"likelihood" gorm:"type:varchar(16);index"`
	Impact             *string    `json:"impact" gorm:"type:varchar(16);index"`
	RiskTemplateID     *uuid.UUID `json:"riskTemplateId" gorm:"type:uuid;index"`

	SourceType string `json:"sourceType" gorm:"type:varchar(32);not null"`
	DedupeKey  string `json:"dedupeKey" gorm:"type:text;not null;default:''"`

	ReviewDeadline          *time.Time `json:"reviewDeadline" gorm:"index"`
	LastReviewedAt          *time.Time `json:"lastReviewedAt"`
	AcceptanceJustification *string    `json:"acceptanceJustification" gorm:"type:text"`

	FirstSeenAt time.Time `json:"firstSeenAt" gorm:"not null"`
	LastSeenAt  time.Time `json:"lastSeenAt" gorm:"not null"`

	SystemSecurityPlan *relational.SystemSecurityPlan `json:"-" gorm:"foreignKey:SSPID;references:ID"`
	OwnerAssignments   []RiskOwnerAssignment          `json:"ownerAssignments,omitempty" gorm:"foreignKey:RiskID;constraint:OnDelete:CASCADE"`
}

func (Risk) TableName() string {
	return "risk_register_risks"
}

func (r *Risk) BeforeCreate(tx *gorm.DB) error {
	if r.ID == nil {
		id := uuid.New()
		r.ID = &id
	}

	now := time.Now().UTC()
	if r.Status == "" {
		r.Status = string(RiskStatusOpen)
	}
	if r.SourceType == "" {
		r.SourceType = string(RiskSourceTypeManual)
	}
	if r.FirstSeenAt.IsZero() {
		r.FirstSeenAt = now
	}
	if r.LastSeenAt.IsZero() {
		r.LastSeenAt = now
	}

	if !RiskStatus(r.Status).IsValid() {
		return fmt.Errorf("invalid risk status: %s", r.Status)
	}
	if !RiskSourceType(r.SourceType).IsValid() {
		return fmt.Errorf("invalid risk source type: %s", r.SourceType)
	}
	if r.Likelihood != nil && !RiskLevel(*r.Likelihood).IsValid() {
		return fmt.Errorf("invalid likelihood: %s", *r.Likelihood)
	}
	if r.Impact != nil && !RiskLevel(*r.Impact).IsValid() {
		return fmt.Errorf("invalid impact: %s", *r.Impact)
	}

	return nil
}

func EnsureIndexes(db *gorm.DB) error {
	stmts := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_register_dedupe_active ON risk_register_risks (dedupe_key) WHERE status <> 'closed' AND dedupe_key <> ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_risk_owner_primary_unique ON risk_owner_assignments (risk_id) WHERE is_primary = true`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
}
