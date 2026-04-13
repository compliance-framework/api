package risks

import (
	"errors"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	RiskScoreBucketDay = "day"
)

type RiskScore struct {
	relational.UUIDModel
	CreatedAt time.Time `json:"createdAt"`

	RiskID            uuid.UUID  `json:"riskId" gorm:"type:uuid;not null;index"`
	SSPID             uuid.UUID  `json:"sspId" gorm:"type:uuid;not null;index"`
	OccurredAt        time.Time  `json:"occurredAt" gorm:"not null;index"`
	ActorUserID       *uuid.UUID `json:"actorUserId" gorm:"type:uuid;index"`
	SourceEventType   string     `json:"sourceEventType" gorm:"type:varchar(64);not null;index"`
	Status            string     `json:"status" gorm:"type:varchar(64);not null;index"`
	Likelihood        *string    `json:"likelihood" gorm:"type:varchar(16)"`
	Impact            *string    `json:"impact" gorm:"type:varchar(16)"`
	BaselineScore     int        `json:"baselineScore" gorm:"not null"`
	ResidualScore     int        `json:"residualScore" gorm:"not null"`
	OpenBaselineScore int        `json:"openBaselineScore" gorm:"not null"`
	OpenResidualScore int        `json:"openResidualScore" gorm:"not null"`
}

func (RiskScore) TableName() string {
	return "risk_scores"
}

func (s *RiskScore) BeforeCreate(_ *gorm.DB) error {
	if s.ID == nil {
		id := uuid.New()
		s.ID = &id
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	if s.OccurredAt.IsZero() {
		s.OccurredAt = s.CreatedAt
	}
	return nil
}

func (s *RiskScore) BeforeUpdate(_ *gorm.DB) error {
	return errors.New("risk scores are append-only")
}

func (s *RiskScore) BeforeDelete(_ *gorm.DB) error {
	return errors.New("risk scores are append-only")
}

type RiskScoreTimeseriesPoint struct {
	BucketStart       time.Time `json:"bucketStart" gorm:"column:bucket_start"`
	OpenBaselineScore int       `json:"openBaselineScore" gorm:"column:open_baseline_score"`
	OpenResidualScore int       `json:"openResidualScore" gorm:"column:open_residual_score"`
}

func RiskLevelRank(level RiskLevel) (int, bool) {
	switch NormalizeRiskLevel(string(level)) {
	case RiskLevelNegligible:
		return 1, true
	case RiskLevelLow:
		return 2, true
	case RiskLevelModerate:
		return 3, true
	case RiskLevelHigh:
		return 4, true
	case RiskLevelCritical:
		return 5, true
	default:
		return 0, false
	}
}

func NumericalRiskScore(likelihood, impact *string) (int, bool) {
	if likelihood == nil || impact == nil {
		return 0, false
	}

	likelihoodRank, ok := RiskLevelRank(RiskLevel(*likelihood))
	if !ok {
		return 0, false
	}
	impactRank, ok := RiskLevelRank(RiskLevel(*impact))
	if !ok {
		return 0, false
	}

	return likelihoodRank * impactRank, true
}

func (s *RiskService) RecordRiskScoreSnapshot(tx *gorm.DB, riskID uuid.UUID, sourceEventType RiskEventType, actorUserID *uuid.UUID, occurredAt time.Time) error {
	if tx == nil {
		tx = s.db
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	} else {
		occurredAt = occurredAt.UTC()
	}

	var risk Risk
	if err := tx.Select("id", "ssp_id", "status", "likelihood", "impact").First(&risk, "id = ?", riskID).Error; err != nil {
		return err
	}
	if risk.ID == nil {
		return fmt.Errorf("risk %s missing id", riskID)
	}

	currentScore, hasCurrentScore := NumericalRiskScore(risk.Likelihood, risk.Impact)

	var latest RiskScore
	err := tx.
		Where("risk_id = ?", riskID).
		Order("occurred_at DESC, created_at DESC, id DESC").
		First(&latest).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	hasLatest := err == nil
	if !hasLatest && !hasCurrentScore {
		return nil
	}

	baselineScore := currentScore
	residualScore := currentScore
	if hasLatest {
		baselineScore = latest.BaselineScore
		residualScore = latest.ResidualScore
		if isScoreValueEvent(sourceEventType) && hasCurrentScore {
			residualScore = currentScore
		}
	}

	openBaselineScore := baselineScore
	openResidualScore := residualScore
	if isTerminalRiskStatus(risk.Status) {
		openBaselineScore = 0
		openResidualScore = 0
	}

	score := RiskScore{
		RiskID:            riskID,
		SSPID:             risk.SSPID,
		OccurredAt:        occurredAt,
		ActorUserID:       actorUserID,
		SourceEventType:   string(sourceEventType),
		Status:            risk.Status,
		Likelihood:        risk.Likelihood,
		Impact:            risk.Impact,
		BaselineScore:     baselineScore,
		ResidualScore:     residualScore,
		OpenBaselineScore: openBaselineScore,
		OpenResidualScore: openResidualScore,
	}
	return tx.Create(&score).Error
}

func isScoreValueEvent(eventType RiskEventType) bool {
	switch eventType {
	case RiskEventTypeScoreReassessed, RiskEventTypeScoreUpdated:
		return true
	default:
		return false
	}
}

func isTerminalRiskStatus(status string) bool {
	return status == string(RiskStatusClosed) || status == string(RiskStatusRemediated)
}

func (s *RiskService) ListScoreHistory(riskID uuid.UUID) ([]RiskScore, error) {
	var scores []RiskScore
	if err := s.db.
		Where("risk_id = ?", riskID).
		Order("occurred_at ASC, created_at ASC, id ASC").
		Find(&scores).Error; err != nil {
		return nil, err
	}
	return scores, nil
}

func (s *RiskService) ListScoreTimeseries(sspID *uuid.UUID, from, to time.Time, bucket string) ([]RiskScoreTimeseriesPoint, error) {
	if bucket == "" {
		bucket = RiskScoreBucketDay
	}
	if bucket != RiskScoreBucketDay {
		return nil, newValidationError("bucket must be day")
	}
	if to.Before(from) {
		return nil, newValidationError("to must be greater than or equal to from")
	}

	from = from.UTC()
	to = to.UTC()

	query := `
		WITH buckets AS (
			SELECT generate_series(
				date_trunc('day', ?::timestamptz),
				date_trunc('day', ?::timestamptz),
				interval '1 day'
			) AS bucket_start
		)
		SELECT
			b.bucket_start,
			COALESCE(SUM(latest.open_baseline_score), 0)::int AS open_baseline_score,
			COALESCE(SUM(latest.open_residual_score), 0)::int AS open_residual_score
		FROM buckets b
		LEFT JOIN LATERAL (
			SELECT DISTINCT ON (rs.risk_id)
				rs.risk_id,
				rs.open_baseline_score,
				rs.open_residual_score
			FROM risk_scores rs
			WHERE rs.occurred_at < b.bucket_start + interval '1 day'
			ORDER BY rs.risk_id, rs.occurred_at DESC, rs.created_at DESC, rs.id DESC
		) latest ON true
		GROUP BY b.bucket_start
		ORDER BY b.bucket_start ASC
	`
	args := []any{from, to}
	if sspID != nil {
		query = `
			WITH buckets AS (
				SELECT generate_series(
					date_trunc('day', ?::timestamptz),
					date_trunc('day', ?::timestamptz),
					interval '1 day'
				) AS bucket_start
			)
			SELECT
				b.bucket_start,
				COALESCE(SUM(latest.open_baseline_score), 0)::int AS open_baseline_score,
				COALESCE(SUM(latest.open_residual_score), 0)::int AS open_residual_score
			FROM buckets b
			LEFT JOIN LATERAL (
				SELECT DISTINCT ON (rs.risk_id)
					rs.risk_id,
					rs.open_baseline_score,
					rs.open_residual_score
				FROM risk_scores rs
				WHERE rs.ssp_id = ?
					AND rs.occurred_at < b.bucket_start + interval '1 day'
				ORDER BY rs.risk_id, rs.occurred_at DESC, rs.created_at DESC, rs.id DESC
			) latest ON true
			GROUP BY b.bucket_start
			ORDER BY b.bucket_start ASC
		`
		args = []any{from, to, *sspID}
	}

	var rows []RiskScoreTimeseriesPoint
	if err := s.db.Raw(query, args...).Scan(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}
