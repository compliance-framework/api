package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	oscalTypes_1_1_3 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type stubRiverClient struct {
	params []river.InsertManyParams
	err    error
}

func (s *stubRiverClient) InsertMany(_ context.Context, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error) {
	s.params = append(s.params, params...)
	if s.err != nil {
		return nil, s.err
	}
	return []*rivertype.JobInsertResult{}, nil
}

func newRiskWorkersTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.User{},
		&relational.SystemSecurityPlan{},
		&relational.SystemCharacteristics{},
		&relational.Evidence{},
		&relational.Labels{},
		&relational.AssessmentSubject{},
		&relational.SystemComponent{},
		&relational.InventoryItem{},
		&riskrel.Risk{},
		&riskrel.RiskOwnerAssignment{},
		&riskrel.RiskEvidenceLink{},
		&riskrel.RiskSubjectLink{},
		&riskrel.RiskEvent{},
	))
	return db
}

func createTestRiskWithOwner(t *testing.T, db *gorm.DB, status riskrel.RiskStatus, reviewDeadline *time.Time, lastSeenAt time.Time) (riskrel.Risk, uuid.UUID) {
	t.Helper()
	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)

	ownerID := uuid.New()
	riskID := uuid.New()
	r := riskrel.Risk{
		UUIDModel:      relational.UUIDModel{ID: &riskID},
		Title:          "Test Risk",
		Description:    "Test Risk Description",
		Status:         string(status),
		SSPID:          sspID,
		SourceType:     string(riskrel.RiskSourceTypeManual),
		ReviewDeadline: reviewDeadline,
		FirstSeenAt:    time.Now().UTC().Add(-24 * time.Hour),
		LastSeenAt:     lastSeenAt,
	}
	require.NoError(t, db.Create(&r).Error)
	require.NoError(t, db.Create(&riskrel.RiskOwnerAssignment{
		RiskID:    riskID,
		OwnerKind: "user",
		OwnerRef:  ownerID.String(),
		IsPrimary: true,
	}).Error)
	return r, ownerID
}

func createTestUser(t *testing.T, db *gorm.DB, id uuid.UUID, subscribed bool) {
	t.Helper()
	require.NoError(t, db.Model(&relational.User{}).Create(map[string]interface{}{
		"id":                            id,
		"email":                         id.String() + "@example.com",
		"first_name":                    "Risk",
		"last_name":                     "Owner",
		"auth_method":                   "password",
		"risk_notifications_subscribed": subscribed,
	}).Error)
}

func TestRiskReviewDeadlineReminderScannerWorker_EnqueuesPerUserOwner(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()
	now := time.Now().UTC()
	reviewDeadline := now.Add(29 * 24 * time.Hour)
	_, _ = createTestRiskWithOwner(t, db, riskrel.RiskStatusRiskAccepted, &reviewDeadline, now)

	w := NewRiskReviewDeadlineReminderScannerWorker(db, client, logger)
	err := w.Work(context.Background(), &river.Job[RiskReviewDeadlineReminderScannerArgs]{})
	require.NoError(t, err)
	require.Len(t, client.params, 1)

	args, ok := client.params[0].Args.(RiskReviewDueReminderArgs)
	require.True(t, ok)
	assert.Equal(t, "30d", args.ReminderWindow)
	assert.Equal(t, 24*time.Hour, client.params[0].InsertOpts.UniqueOpts.ByPeriod)
}

func TestRiskReviewOverdueEscalationScannerWorker_EnqueuesEscalationAndReopen(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()
	now := time.Now().UTC()
	reviewDeadline := now.Add(-31 * 24 * time.Hour)
	_, _ = createTestRiskWithOwner(t, db, riskrel.RiskStatusRiskAccepted, &reviewDeadline, now.Add(-40*24*time.Hour))

	w := NewRiskReviewOverdueEscalationScannerWorker(db, client, logger, true, 30)
	err := w.Work(context.Background(), &river.Job[RiskReviewOverdueEscalationScannerArgs]{})
	require.NoError(t, err)

	var escalationCount, reopenCount int
	for _, p := range client.params {
		switch p.Args.(type) {
		case RiskReviewOverdueEscalationArgs:
			escalationCount++
		case RiskReviewOverdueReopenArgs:
			reopenCount++
		}
	}
	assert.Equal(t, 1, escalationCount)
	assert.Equal(t, 1, reopenCount)
}

func TestRiskStaleRiskScannerWorker_EnqueuesWeeklyReminder(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()
	now := time.Now().UTC()
	_, _ = createTestRiskWithOwner(t, db, riskrel.RiskStatusOpen, nil, now.Add(-31*24*time.Hour))

	w := NewRiskStaleRiskScannerWorker(db, client, logger)
	err := w.Work(context.Background(), &river.Job[RiskStaleRiskScannerArgs]{})
	require.NoError(t, err)
	require.Len(t, client.params, 1)

	_, ok := client.params[0].Args.(RiskStaleOpenReminderArgs)
	require.True(t, ok)
	assert.Equal(t, 7*24*time.Hour, client.params[0].InsertOpts.UniqueOpts.ByPeriod)
}

func TestRiskEvidenceReconciliationScannerWorker_EnqueuesRepairJobs(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	// Evidence failure without linked risk
	evidenceID := uuid.New()
	require.NoError(t, db.Create(&relational.Evidence{
		UUIDModel: relational.UUIDModel{ID: &evidenceID},
		UUID:      uuid.New(),
		Title:     "failing evidence",
		Start:     time.Now().UTC().Add(-time.Hour),
		End:       time.Now().UTC(),
		Status:    datatypes.NewJSONType(oscalTypes_1_1_3.ObjectiveStatus{State: relational.EvidenceStatusNotSatisfied}),
	}).Error)

	// Duplicate active risks by dedupe key
	dupSSP := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &dupSSP}}).Error)
	r1ID := uuid.New()
	r2ID := uuid.New()
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:   relational.UUIDModel{ID: &r1ID},
		Title:       "dup1",
		Description: "dup1",
		Status:      string(riskrel.RiskStatusOpen),
		SSPID:       dupSSP,
		SourceType:  string(riskrel.RiskSourceTypeManual),
		DedupeKey:   "dup-key",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:   relational.UUIDModel{ID: &r2ID},
		Title:       "dup2",
		Description: "dup2",
		Status:      string(riskrel.RiskStatusInvestigating),
		SSPID:       dupSSP,
		SourceType:  string(riskrel.RiskSourceTypeManual),
		DedupeKey:   "dup-key",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
	}).Error)

	w := NewRiskEvidenceReconciliationScannerWorker(db, client, logger)
	err := w.Work(context.Background(), &river.Job[RiskEvidenceReconciliationScannerArgs]{})
	require.NoError(t, err)

	var sawEvidenceRepair, sawEvidenceRepairWithRetries, sawDuplicateRepair bool
	for _, p := range client.params {
		switch args := p.Args.(type) {
		case RiskProcessEvidenceFailureArgs:
			if args.EvidenceID == evidenceID {
				sawEvidenceRepair = true
				if p.InsertOpts != nil && p.InsertOpts.MaxAttempts == 5 {
					sawEvidenceRepairWithRetries = true
				}
			}
		case RiskReconcileDuplicatesArgs:
			if args.DedupeKey == "dup-key" {
				sawDuplicateRepair = true
			}
		}
	}
	assert.True(t, sawEvidenceRepair)
	assert.True(t, sawEvidenceRepairWithRetries)
	assert.True(t, sawDuplicateRepair)
}

func TestRiskReconcileDuplicatesWorker_ClosesNewerRisk(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{UUIDModel: relational.UUIDModel{ID: &sspID}}).Error)

	oldID := uuid.New()
	newID := uuid.New()
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:   relational.UUIDModel{ID: &oldID},
		Title:       "old",
		Description: "old",
		Status:      string(riskrel.RiskStatusOpen),
		SSPID:       sspID,
		SourceType:  string(riskrel.RiskSourceTypeManual),
		DedupeKey:   "dup-close",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		CreatedAt:   time.Now().UTC().Add(-time.Hour),
	}).Error)
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:   relational.UUIDModel{ID: &newID},
		Title:       "new",
		Description: "new",
		Status:      string(riskrel.RiskStatusInvestigating),
		SSPID:       sspID,
		SourceType:  string(riskrel.RiskSourceTypeManual),
		DedupeKey:   "dup-close",
		FirstSeenAt: time.Now().UTC(),
		LastSeenAt:  time.Now().UTC(),
		CreatedAt:   time.Now().UTC(),
	}).Error)

	w := NewRiskReconcileDuplicatesWorker(db, logger)
	err := w.Work(context.Background(), &river.Job[RiskReconcileDuplicatesArgs]{Args: RiskReconcileDuplicatesArgs{DedupeKey: "dup-close"}})
	require.NoError(t, err)

	var oldRisk, newRisk riskrel.Risk
	require.NoError(t, db.First(&oldRisk, "id = ?", oldID).Error)
	require.NoError(t, db.First(&newRisk, "id = ?", newID).Error)
	assert.Equal(t, string(riskrel.RiskStatusOpen), oldRisk.Status)
	assert.Equal(t, string(riskrel.RiskStatusClosed), newRisk.Status)
}

func TestRiskReviewOverdueReopenWorker_ReopensAcceptedRisk(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	reviewDeadline := time.Now().UTC().Add(-40 * 24 * time.Hour)
	risk, _ := createTestRiskWithOwner(t, db, riskrel.RiskStatusRiskAccepted, &reviewDeadline, time.Now().UTC())

	w := NewRiskReviewOverdueReopenWorker(db, logger)
	err := w.Work(context.Background(), &river.Job[RiskReviewOverdueReopenArgs]{
		Args: RiskReviewOverdueReopenArgs{
			RiskID:        *risk.ID,
			ThresholdDays: 30,
		},
	})
	require.NoError(t, err)

	var updated riskrel.Risk
	require.NoError(t, db.First(&updated, "id = ?", risk.ID).Error)
	assert.Equal(t, string(riskrel.RiskStatusInvestigating), updated.Status)
	assert.Nil(t, updated.ReviewDeadline)
}

func TestRiskReviewDueReminderWorker_RespectsRiskSubscription(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	now := time.Now().UTC()
	reviewDeadline := now.Add(7 * 24 * time.Hour)
	risk, ownerID := createTestRiskWithOwner(t, db, riskrel.RiskStatusRiskAccepted, &reviewDeadline, now)
	createTestUser(t, db, ownerID, false)

	mockEmail := &MockEmailService{}
	userRepo := NewGORMUserRepository(db)
	worker := NewRiskReviewDueReminderWorker(db, mockEmail, userRepo, "https://app.example.com", logger)

	err := worker.Work(context.Background(), &river.Job[RiskReviewDueReminderArgs]{
		Args: RiskReviewDueReminderArgs{
			RiskID:      *risk.ID,
			OwnerUserID: ownerID,
		},
	})
	require.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestRiskReviewDueReminderWorker_SendsWhenSubscribed(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	now := time.Now().UTC()
	reviewDeadline := now.Add(7 * 24 * time.Hour)
	risk, ownerID := createTestRiskWithOwner(t, db, riskrel.RiskStatusRiskAccepted, &reviewDeadline, now)
	createTestUser(t, db, ownerID, true)

	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "risk-review-due-reminder", mock.Anything).Return("<html>ok</html>", "ok", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", mock.Anything, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == ownerID.String()+"@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "risk-msg"}, nil)

	userRepo := NewGORMUserRepository(db)
	worker := NewRiskReviewDueReminderWorker(db, mockEmail, userRepo, "https://app.example.com", logger)
	err := worker.Work(context.Background(), &river.Job[RiskReviewDueReminderArgs]{
		Args: RiskReviewDueReminderArgs{
			RiskID:      *risk.ID,
			OwnerUserID: ownerID,
		},
	})
	require.NoError(t, err)
	mockEmail.AssertExpectations(t)
}
