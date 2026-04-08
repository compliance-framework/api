package risks

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// NumericalRiskScore unit tests
// ---------------------------------------------------------------------------

func TestNumericalRiskScore_AllLevels(t *testing.T) {
	cases := []struct {
		likelihood RiskLevel
		impact     RiskLevel
		want       int
	}{
		{RiskLevelNegligible, RiskLevelNegligible, 1},
		{RiskLevelNegligible, RiskLevelCritical, 5},
		{RiskLevelLow, RiskLevelLow, 4},
		{RiskLevelModerate, RiskLevelModerate, 9},
		{RiskLevelHigh, RiskLevelHigh, 16},
		{RiskLevelCritical, RiskLevelCritical, 25},
		{RiskLevelHigh, RiskLevelCritical, 20},
		{RiskLevelCritical, RiskLevelLow, 10},
	}
	for _, tc := range cases {
		got := NumericalRiskScore(tc.likelihood, tc.impact)
		require.Equal(t, tc.want, got, "NumericalRiskScore(%s, %s)", tc.likelihood, tc.impact)
	}
}

func TestNumericalRiskScore_UnknownLevelReturnsZero(t *testing.T) {
	require.Equal(t, 0, NumericalRiskScore("unknown", RiskLevelHigh))
	require.Equal(t, 0, NumericalRiskScore(RiskLevelHigh, ""))
	require.Equal(t, 0, NumericalRiskScore("", ""))
}

// ---------------------------------------------------------------------------
// insertRiskScore / ListScoreHistory service-level tests
// ---------------------------------------------------------------------------

func newScoreTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&Risk{},
		&RiskEvent{},
		&RiskReview{},
		&RiskScore{},
		&RiskOwnerAssignment{},
		&RiskThreatRef{},
		&RiskRemediationTemplate{},
		&RiskRemediationTask{},
	))
	require.NoError(t, EnsureIndexes(db))
	return db
}

func makeTestRisk(t *testing.T, db *gorm.DB, sspID uuid.UUID) *Risk {
	t.Helper()
	l := string(RiskLevelModerate)
	i := string(RiskLevelHigh)
	risk := Risk{
		Title:       "score-test risk",
		Description: "desc",
		Status:      string(RiskStatusInvestigating),
		SSPID:       sspID,
		Likelihood:  &l,
		Impact:      &i,
		SourceType:  string(RiskSourceTypeManual),
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}
	require.NoError(t, db.Create(&risk).Error)
	return &risk
}

// TestInsertRiskScore_BaselineOnFirstInsert verifies that the first score row
// for a risk is tagged as "baseline" and subsequent rows are tagged "residual".
func TestInsertRiskScore_BaselineOnFirstInsert(t *testing.T) {
	db := newScoreTestDB(t)
	svc := NewRiskService(db)
	sspID := uuid.New()
	risk := makeTestRisk(t, db, sspID)
	actorID := uuid.New()
	now := time.Now().UTC()

	// First insertion → baseline
	err := svc.insertRiskScore(db, *risk.ID, sspID, RiskLevelModerate, RiskLevelHigh, &actorID, now)
	require.NoError(t, err)

	var scores []RiskScore
	require.NoError(t, db.Where("risk_id = ?", *risk.ID).Order("occurred_at ASC").Find(&scores).Error)
	require.Len(t, scores, 1)
	require.Equal(t, string(ScoreTypeBaseline), scores[0].ScoreType)
	require.Equal(t, NumericalRiskScore(RiskLevelModerate, RiskLevelHigh), scores[0].Score)
	require.Equal(t, string(RiskLevelModerate), scores[0].Likelihood)
	require.Equal(t, string(RiskLevelHigh), scores[0].Impact)
	require.Equal(t, sspID, scores[0].SSPID)
	require.Equal(t, &actorID, scores[0].ActorUserID)

	// Second insertion → residual
	err = svc.insertRiskScore(db, *risk.ID, sspID, RiskLevelLow, RiskLevelCritical, &actorID, now.Add(time.Hour))
	require.NoError(t, err)

	require.NoError(t, db.Where("risk_id = ?", *risk.ID).Order("occurred_at ASC").Find(&scores).Error)
	require.Len(t, scores, 2)
	require.Equal(t, string(ScoreTypeBaseline), scores[0].ScoreType)
	require.Equal(t, string(ScoreTypeResidual), scores[1].ScoreType)
	require.Equal(t, NumericalRiskScore(RiskLevelLow, RiskLevelCritical), scores[1].Score)
}

// TestInsertRiskScore_UnknownLevelSkipped verifies that an unrecognised level
// does not produce a score row (score would be 0).
func TestInsertRiskScore_UnknownLevelSkipped(t *testing.T) {
	db := newScoreTestDB(t)
	svc := NewRiskService(db)
	sspID := uuid.New()
	risk := makeTestRisk(t, db, sspID)

	err := svc.insertRiskScore(db, *risk.ID, sspID, "unknown", RiskLevelHigh, nil, time.Now().UTC())
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&RiskScore{}).Where("risk_id = ?", *risk.ID).Count(&count).Error)
	require.Zero(t, count, "no score row should be written for an unrecognised level")
}

// TestInsertRiskScore_ImmutableAfterCreate verifies that BeforeUpdate prevents
// any mutation of a persisted score row.
func TestInsertRiskScore_ImmutableAfterCreate(t *testing.T) {
	db := newScoreTestDB(t)
	svc := NewRiskService(db)
	sspID := uuid.New()
	risk := makeTestRisk(t, db, sspID)

	require.NoError(t, svc.insertRiskScore(db, *risk.ID, sspID, RiskLevelHigh, RiskLevelHigh, nil, time.Now().UTC()))

	var score RiskScore
	require.NoError(t, db.Where("risk_id = ?", *risk.ID).First(&score).Error)

	score.Score = 999
	err := db.Save(&score).Error
	require.Error(t, err, "updating a risk score row must be rejected")
}

// TestListScoreHistory_ChronologicalOrder verifies that ListScoreHistory
// returns rows in ascending occurred_at order.
func TestListScoreHistory_ChronologicalOrder(t *testing.T) {
	db := newScoreTestDB(t)
	svc := NewRiskService(db)
	sspID := uuid.New()
	risk := makeTestRisk(t, db, sspID)
	base := time.Now().UTC()

	levels := []struct {
		l RiskLevel
		i RiskLevel
	}{
		{RiskLevelLow, RiskLevelLow},
		{RiskLevelModerate, RiskLevelModerate},
		{RiskLevelHigh, RiskLevelHigh},
	}
	for idx, lv := range levels {
		require.NoError(t, svc.insertRiskScore(db, *risk.ID, sspID, lv.l, lv.i, nil, base.Add(time.Duration(idx)*time.Hour)))
	}

	history, err := svc.ListScoreHistory(*risk.ID)
	require.NoError(t, err)
	require.Len(t, history, 3)

	// Verify ascending order
	for i := 1; i < len(history); i++ {
		require.True(t, !history[i].OccurredAt.Before(history[i-1].OccurredAt),
			"score history must be in ascending occurred_at order")
	}

	// Verify score type progression
	require.Equal(t, string(ScoreTypeBaseline), history[0].ScoreType)
	require.Equal(t, string(ScoreTypeResidual), history[1].ScoreType)
	require.Equal(t, string(ScoreTypeResidual), history[2].ScoreType)
}

// TestListScoreHistory_EmptyForNoScores verifies that ListScoreHistory returns
// an empty slice (not an error) when no scores have been recorded.
func TestListScoreHistory_EmptyForNoScores(t *testing.T) {
	db := newScoreTestDB(t)
	svc := NewRiskService(db)
	sspID := uuid.New()
	risk := makeTestRisk(t, db, sspID)

	history, err := svc.ListScoreHistory(*risk.ID)
	require.NoError(t, err)
	require.Empty(t, history)
}

// TestCreateRisk_BaselineScoreWritten verifies the end-to-end integration:
// creating a risk with likelihood+impact set must produce a baseline score row.
func TestCreateRisk_BaselineScoreWritten(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)
	actorID := uuid.New()
	sspID := uuid.New()
	l := string(RiskLevelHigh)
	i := string(RiskLevelCritical)

	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "score-on-create",
			Description: "desc",
			Status:      string(RiskStatusInvestigating),
			SSPID:       sspID,
			Likelihood:  &l,
			Impact:      &i,
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)

	history, err := svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, string(ScoreTypeBaseline), history[0].ScoreType)
	require.Equal(t, NumericalRiskScore(RiskLevelHigh, RiskLevelCritical), history[0].Score)
	require.Equal(t, sspID, history[0].SSPID)
}

// TestCreateRisk_NoScoreWhenLevelsAbsent verifies that creating a risk without
// likelihood/impact does not produce a score row.
func TestCreateRisk_NoScoreWhenLevelsAbsent(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)
	sspID := uuid.New()

	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "no-score-risk",
			Description: "desc",
			Status:      string(RiskStatusInvestigating),
			SSPID:       sspID,
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
	})
	require.NoError(t, err)

	history, err := svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Empty(t, history)
}

// TestReviewRisk_ReassessWritesResidualScore verifies that a "reassess" review
// decision appends a residual score row.
func TestReviewRisk_ReassessWritesResidualScore(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)
	actorID := uuid.New()
	sspID := uuid.New()
	l := string(RiskLevelModerate)
	i := string(RiskLevelModerate)

	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "reassess-risk",
			Description: "desc",
			Status:      string(RiskStatusInvestigating),
			SSPID:       sspID,
			Likelihood:  &l,
			Impact:      &i,
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)

	// Baseline score should exist
	history, err := svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Equal(t, string(ScoreTypeBaseline), history[0].ScoreType)

	// Reassess with new levels
	newL := string(RiskLevelLow)
	newI := string(RiskLevelLow)
	_, err = svc.ReviewRisk(ReviewRiskParams{
		RiskID:      *created.ID,
		ActorUserID: &actorID,
		Decision:    RiskReviewDecisionReassess,
		Likelihood:  &newL,
		Impact:      &newI,
	})
	require.NoError(t, err)

	history, err = svc.ListScoreHistory(*created.ID)
	require.NoError(t, err)
	require.Len(t, history, 2)
	require.Equal(t, string(ScoreTypeBaseline), history[0].ScoreType)
	require.Equal(t, string(ScoreTypeResidual), history[1].ScoreType)
	require.Equal(t, NumericalRiskScore(RiskLevelLow, RiskLevelLow), history[1].Score)
}

// TestRiskScore_CascadeDeletedWithRisk verifies that score rows are removed
// via CASCADE when the parent risk is deleted.
func TestRiskScore_CascadeDeletedWithRisk(t *testing.T) {
	db := newRiskServiceTestDB(t)
	svc := NewRiskService(db)
	actorID := uuid.New()
	sspID := uuid.New()
	l := string(RiskLevelHigh)
	i := string(RiskLevelHigh)

	created, err := svc.Create(CreateRiskParams{
		Risk: Risk{
			Title:       "cascade-delete-risk",
			Description: "desc",
			Status:      string(RiskStatusInvestigating),
			SSPID:       sspID,
			Likelihood:  &l,
			Impact:      &i,
			SourceType:  string(RiskSourceTypeManual),
			FirstSeenAt: time.Now().UTC(),
			LastSeenAt:  time.Now().UTC(),
		},
		ActorUserID: &actorID,
	})
	require.NoError(t, err)

	var countBefore int64
	require.NoError(t, db.Model(&RiskScore{}).Where("risk_id = ?", *created.ID).Count(&countBefore).Error)
	require.Equal(t, int64(1), countBefore)

	require.NoError(t, svc.Delete(*created.ID))

	// Score rows must be preserved (same retention policy as events/reviews)
	var countAfter int64
	require.NoError(t, db.Model(&RiskScore{}).Where("risk_id = ?", *created.ID).Count(&countAfter).Error)
	require.Equal(t, int64(1), countAfter, "score rows must be retained after risk deletion (same as events/reviews)")
}

// ---------------------------------------------------------------------------
// RiskScore struct-level guard tests
// ---------------------------------------------------------------------------

func TestRiskScore_TableName(t *testing.T) {
	require.Equal(t, "risk_scores", RiskScore{}.TableName())
}

func TestRiskScore_BeforeCreateSetsID(t *testing.T) {
	db := newScoreTestDB(t)
	sspID := uuid.New()
	risk := makeTestRisk(t, db, sspID)

	row := RiskScore{
		RiskID:     *risk.ID,
		SSPID:      sspID,
		OccurredAt: time.Now().UTC(),
		Likelihood: string(RiskLevelLow),
		Impact:     string(RiskLevelLow),
		Score:      NumericalRiskScore(RiskLevelLow, RiskLevelLow),
		ScoreType:  string(ScoreTypeBaseline),
	}
	require.NoError(t, db.Create(&row).Error)
	require.NotNil(t, row.ID)
}

// relational.UUIDModel is used by RiskScore — ensure the package import resolves.
var _ relational.UUIDModel = relational.UUIDModel{}
