package risks

import (
	"errors"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ScoreType distinguishes the first-ever score for a risk (baseline) from all
// subsequent reassessments (residual). The baseline represents the inherent
// risk before any controls are applied; residual scores track how the risk
// changes as mitigations are implemented.
type ScoreType string

const (
	// ScoreTypeBaseline is assigned to the first RiskScore recorded for a risk.
	ScoreTypeBaseline ScoreType = "baseline"
	// ScoreTypeResidual is assigned to every subsequent score change.
	ScoreTypeResidual ScoreType = "residual"
)

// levelRank maps a canonical RiskLevel to its 1-based ordinal rank on the
// standard 5×5 risk matrix (NIST SP 800-30 / ISO 27005).
//
//	negligible → 1
//	low        → 2
//	moderate   → 3
//	high       → 4
//	critical   → 5
//
// An unrecognised level returns 0 so that callers can detect a missing value.
func levelRank(level RiskLevel) int {
	switch level {
	case RiskLevelNegligible:
		return 1
	case RiskLevelLow:
		return 2
	case RiskLevelModerate:
		return 3
	case RiskLevelHigh:
		return 4
	case RiskLevelCritical:
		return 5
	default:
		return 0
	}
}

// NumericalRiskScore computes the integer score for a given likelihood and
// impact pair using the standard matrix product: rank(L) × rank(I).
//
// The result ranges from 1 (negligible × negligible) to 25 (critical ×
// critical). A score of 0 is returned when either level is unrecognised,
// allowing callers to treat 0 as "not calculable".
//
// Severity bands (aligned with the existing RiskSeverityHeatmapWidget):
//
//	 1–4   Low
//	 5–9   Moderate
//	10–16  High
//	17–25  Critical
func NumericalRiskScore(likelihood, impact RiskLevel) int {
	l := levelRank(likelihood)
	i := levelRank(impact)
	if l == 0 || i == 0 {
		return 0
	}
	return l * i
}

// RiskScore is an append-only record capturing the numerical risk score at a
// specific point in time. It is written atomically alongside the risk_events
// row whenever a score-bearing change occurs (risk creation with
// likelihood/impact set, or a "reassess" review decision).
//
// The ssp_id column is denormalised from the parent Risk to allow efficient
// SSP-level aggregate queries without joining through risk_register_risks.
type RiskScore struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`

	RiskID      uuid.UUID  `json:"riskId"      gorm:"type:uuid;not null;index"`
	SSPID       uuid.UUID  `json:"sspId"       gorm:"type:uuid;not null;index"`
	ActorUserID *uuid.UUID `json:"actorUserId" gorm:"type:uuid;index"`
	OccurredAt  time.Time  `json:"occurredAt"  gorm:"not null;index"`

	Likelihood string `json:"likelihood" gorm:"type:varchar(16);not null"`
	Impact     string `json:"impact"     gorm:"type:varchar(16);not null"`
	Score      int    `json:"score"      gorm:"not null"`
	ScoreType  string `json:"scoreType"  gorm:"type:varchar(16);not null;index"`

	Risk *Risk `json:"-" gorm:"foreignKey:RiskID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RiskScore) TableName() string {
	return "risk_scores"
}

func (s *RiskScore) BeforeCreate(_ *gorm.DB) error {
	if s.ID == nil {
		id := uuid.New()
		s.ID = &id
	}
	return nil
}

// BeforeUpdate prevents any mutation of a persisted score row. Scores are
// immutable audit records; corrections must be appended as new rows.
func (s *RiskScore) BeforeUpdate(_ *gorm.DB) error {
	return errors.New("risk scores are append-only")
}

// BeforeDelete prevents deletion of score rows to preserve the full audit
// trail. Scores are only removed via CASCADE when the parent risk is deleted.
func (s *RiskScore) BeforeDelete(_ *gorm.DB) error {
	return errors.New("risk scores are append-only")
}
