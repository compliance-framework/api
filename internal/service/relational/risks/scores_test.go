package risks

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRiskLevelRankAndNumericalRiskScore(t *testing.T) {
	cases := []struct {
		level RiskLevel
		rank  int
	}{
		{RiskLevelNegligible, 1},
		{RiskLevelLow, 2},
		{RiskLevelModerate, 3},
		{RiskLevelMediumLegacy, 3},
		{RiskLevelHigh, 4},
		{RiskLevelCritical, 5},
	}
	for _, tc := range cases {
		rank, ok := RiskLevelRank(tc.level)
		require.True(t, ok)
		require.Equal(t, tc.rank, rank)
	}

	likelihood := "medium"
	impact := "critical"
	score, ok := NumericalRiskScore(&likelihood, &impact)
	require.True(t, ok)
	require.Equal(t, 15, score)

	score, ok = NumericalRiskScore(nil, &impact)
	require.False(t, ok)
	require.Equal(t, 0, score)
}

func TestRiskScoreSnapshots(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	actorID := uuid.New()
	sspID := uuid.New()
	low := "low"
	high := "high"
	critical := "critical"
	now := time.Now().UTC()

	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "scored risk",
			Description: "desc",
			Status:      string(RiskStatusInvestigating),
			SSPID:       sspID,
			Likelihood:  &low,
			Impact:      &high,
			FirstSeenAt: now,
			LastSeenAt:  now,
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)

	history, err := svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, 8, history[0].BaselineScore)
	require.Equal(t, 8, history[0].ResidualScore)
	require.Equal(t, 8, history[0].OpenBaselineScore)
	require.Equal(t, 8, history[0].OpenResidualScore)
	require.Equal(t, string(RiskEventTypeCreated), history[0].SourceEventType)

	reviewedAt := now.Add(time.Hour)
	reassessed, err := svc.ReviewRisk(ReviewRiskParams{
		RiskID:      *created.ID,
		ActorUserID: &actorID,
		ReviewedAt:  &reviewedAt,
		Decision:    RiskReviewDecisionReassess,
		Likelihood:  &low,
		Impact:      &critical,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusInvestigating), reassessed.Status)

	history, err = svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 2)
	require.Equal(t, 8, history[1].BaselineScore)
	require.Equal(t, 10, history[1].ResidualScore)
	require.Equal(t, 8, history[1].OpenBaselineScore)
	require.Equal(t, 10, history[1].OpenResidualScore)
	require.Equal(t, string(RiskEventTypeScoreReassessed), history[1].SourceEventType)

	accepted, err := svc.AcceptRisk(AcceptRiskParams{
		RiskID:         *created.ID,
		ActorUserID:    &actorID,
		Justification:  "accepted risk remains tracked",
		ReviewDeadline: now.Add(30 * 24 * time.Hour),
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusRiskAccepted), accepted.Status)

	history, err = svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 3)
	require.Equal(t, 8, history[2].OpenBaselineScore)
	require.Equal(t, 10, history[2].OpenResidualScore)

	acceptedCopy := *accepted
	oldStatus := acceptedCopy.Status
	acceptedCopy.Status = string(RiskStatusClosed)
	closed, err := svc.Update(UpdateRiskParams{
		Risk:          &acceptedCopy,
		ActorUserID:   &actorID,
		OldStatus:     oldStatus,
		StatusChanged: true,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusClosed), closed.Status)

	history, err = svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 4)
	var closedScore RiskScore
	require.NoError(t, db.Where("risk_id = ? AND status = ?", *created.ID, string(RiskStatusClosed)).First(&closedScore).Error)
	require.Equal(t, 8, closedScore.BaselineScore)
	require.Equal(t, 10, closedScore.ResidualScore)
	require.Equal(t, 0, closedScore.OpenBaselineScore)
	require.Equal(t, 0, closedScore.OpenResidualScore)

	closedCopy := *closed
	oldStatus = closedCopy.Status
	closedCopy.Status = string(RiskStatusOpen)
	reopened, err := svc.Update(UpdateRiskParams{
		Risk:          &closedCopy,
		ActorUserID:   &actorID,
		OldStatus:     oldStatus,
		StatusChanged: true,
	})
	require.NoError(t, err)
	require.Equal(t, string(RiskStatusOpen), reopened.Status)

	history, err = svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 5)
	var reopenedScore RiskScore
	require.NoError(t, db.Where("risk_id = ? AND status = ?", *created.ID, string(RiskStatusOpen)).First(&reopenedScore).Error)
	require.Equal(t, 8, reopenedScore.OpenBaselineScore)
	require.Equal(t, 10, reopenedScore.OpenResidualScore)
}

func TestRiskScoreSnapshotFirstCompleteScoreBecomesBaseline(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	riskID := uuid.New()
	sspID := uuid.New()
	require.NoError(t, db.Create(&Risk{
		UUIDModel:   relational.UUIDModel{ID: &riskID},
		Title:       "unscored",
		Description: "desc",
		Status:      string(RiskStatusOpen),
		SSPID:       sspID,
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	require.NoError(t, svc.RecordRiskScoreSnapshot(db, riskID, RiskEventTypeCreated, nil, time.Now().UTC()))
	history, err := svc.ListScoreHistory(riskID)
	require.NoError(t, err)
	require.Empty(t, history)

	low := "low"
	critical := "critical"
	require.NoError(t, db.Model(&Risk{}).Where("id = ?", riskID).Updates(map[string]any{
		"likelihood": low,
		"impact":     critical,
	}).Error)
	require.NoError(t, svc.RecordRiskScoreSnapshot(db, riskID, RiskEventTypeScoreUpdated, nil, time.Now().UTC()))

	history, err = svc.ListScoreHistory(riskID)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, 10, history[0].BaselineScore)
	require.Equal(t, 10, history[0].ResidualScore)
}

func TestRiskDeleteRecordsZeroContributionScoreSnapshot(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)

	sspID := uuid.New()
	high := "high"
	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "deleted scored risk",
			Description: "desc",
			Status:      string(RiskStatusOpen),
			SSPID:       sspID,
			Likelihood:  &high,
			Impact:      &high,
		},
	})
	require.NoError(t, err)

	require.NoError(t, svc.Delete(*created.ID))

	history, err := svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 2)
	require.Equal(t, string(RiskEventTypeDeleted), history[1].SourceEventType)
	require.Equal(t, RiskScoreStatusDeleted, history[1].Status)
	require.Equal(t, 16, history[1].BaselineScore)
	require.Equal(t, 16, history[1].ResidualScore)
	require.Equal(t, 0, history[1].OpenBaselineScore)
	require.Equal(t, 0, history[1].OpenResidualScore)
}
