package worker

// poam_workers_test.go — unit tests for the three POAM background job scanners.
//
// Tests use an in-memory SQLite database (via gorm/driver/sqlite with CGO) to
// exercise the query logic in isolation, exactly mirroring the pattern used in
// risk_workers_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	poamrel "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

func newPoamWorkersTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&relational.SystemSecurityPlan{},
		&poamrel.PoamItem{},
		&poamrel.PoamItemMilestone{},
		&poamrel.PoamItemRiskLink{},
		&poamrel.PoamItemEvidenceLink{},
		&poamrel.PoamItemControlLink{},
		&poamrel.PoamItemFindingLink{},
	))
	return db
}

// createTestPoamItem inserts a PoamItem with the given status and deadline.
// Returns the created item and the owner UUID.
func createTestPoamItem(
	t *testing.T,
	db *gorm.DB,
	status poamrel.PoamItemStatus,
	deadline *time.Time,
	_ string, // pocEmail — not a direct field; kept for call-site readability
) (poamrel.PoamItem, uuid.UUID) {
	t.Helper()
	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)

	ownerID := uuid.New()
	item := poamrel.PoamItem{
		ID:                    uuid.New(),
		SspID:                 sspID,
		Title:                 "Test POAM Item",
		Description:           "Test POAM Description",
		Status:                string(status),
		SourceType:            "manual",
		PrimaryOwnerUserID:    &ownerID,
		PlannedCompletionDate: deadline,
	}
	require.NoError(t, db.Create(&item).Error)
	return item, ownerID
}

// createTestPoamMilestone inserts a PoamItemMilestone for the given parent item.
func createTestPoamMilestone(
	t *testing.T,
	db *gorm.DB,
	itemID uuid.UUID,
	status string,
	plannedCompletion *time.Time,
) poamrel.PoamItemMilestone {
	t.Helper()
	m := poamrel.PoamItemMilestone{
		ID:                    uuid.New(),
		PoamItemID:            itemID,
		Title:                 "Test Milestone",
		Status:                status,
		PlannedCompletionDate: plannedCompletion,
	}
	require.NoError(t, db.Create(&m).Error)
	return m
}

// ---------------------------------------------------------------------------
// POAM Deadline Reminder Scanner tests
// ---------------------------------------------------------------------------

func TestPoamDeadlineReminderScannerWorker_EnqueuesForApproachingDeadline(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(20 * 24 * time.Hour) // 20 days from now — within 30-day window

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusOpen, &deadline, "poc@example.com")

	w := NewPoamDeadlineReminderScannerWorker(db, client, &stubUserRepository{}, "http://localhost", 30*24*time.Hour, logger)
	err := w.Work(context.Background(), &river.Job[PoamDeadlineReminderScannerArgs]{})
	require.NoError(t, err)

	// Should have enqueued at least one reminder job for this item
	require.NotEmpty(t, client.params, "expected at least one job to be enqueued")
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(PoamDeadlineReminderArgs); ok {
			if args.PoamItemID == item.ID {
				found = true
				assert.Equal(t, "http://localhost/poam-items/"+item.ID.String(), args.PoamURL)
			}
		}
	}
	assert.True(t, found, "expected a PoamDeadlineReminderArgs job for the test item")
}

func TestPoamDeadlineReminderScannerWorker_SkipsItemsOutsideWindow(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(45 * 24 * time.Hour) // 45 days — outside 30-day window

	createTestPoamItem(t, db, poamrel.PoamItemStatusOpen, &deadline, "poc@example.com")

	w := NewPoamDeadlineReminderScannerWorker(db, client, &stubUserRepository{}, "http://localhost", 30*24*time.Hour, logger)
	err := w.Work(context.Background(), &river.Job[PoamDeadlineReminderScannerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no jobs for items outside the reminder window")
}

func TestPoamDeadlineReminderScannerWorker_SkipsCompletedItems(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(5 * 24 * time.Hour) // 5 days — within window

	// Completed items should be excluded
	createTestPoamItem(t, db, poamrel.PoamItemStatusCompleted, &deadline, "poc@example.com")

	w := NewPoamDeadlineReminderScannerWorker(db, client, &stubUserRepository{}, "http://localhost", 30*24*time.Hour, logger)
	err := w.Work(context.Background(), &river.Job[PoamDeadlineReminderScannerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no jobs for completed items")
}

func TestPoamDeadlineReminderScannerWorker_SkipsOverdueItems(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(-1 * 24 * time.Hour) // yesterday — already overdue

	// Overdue items should be handled by the overdue transition scanner, not the reminder
	createTestPoamItem(t, db, poamrel.PoamItemStatusOpen, &deadline, "poc@example.com")

	w := NewPoamDeadlineReminderScannerWorker(db, client, &stubUserRepository{}, "http://localhost", 30*24*time.Hour, logger)
	err := w.Work(context.Background(), &river.Job[PoamDeadlineReminderScannerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no reminder jobs for already-overdue items")
}

// ---------------------------------------------------------------------------
// POAM Overdue Transition Scanner tests
// ---------------------------------------------------------------------------

func TestPoamOverdueTransitionScannerWorker_TransitionsOpenItemsToOverdue(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(-2 * 24 * time.Hour) // 2 days ago — overdue

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusOpen, &deadline, "poc@example.com")

	w := NewPoamOverdueTransitionScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[PoamOverdueTransitionScannerArgs]{})
	require.NoError(t, err)

	// Verify the status was transitioned in the DB
	var updated poamrel.PoamItem
	require.NoError(t, db.First(&updated, "id = ?", item.ID).Error)
	assert.Equal(t, string(poamrel.PoamItemStatusOverdue), updated.Status, "expected status to be transitioned to overdue")

	// Verify a notification job was enqueued
	require.NotEmpty(t, client.params, "expected a notification job to be enqueued")
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(PoamOverdueNotificationArgs); ok {
			if args.PoamItemID == item.ID {
				found = true
			}
		}
	}
	assert.True(t, found, "expected a PoamOverdueNotificationArgs job for the transitioned item")
}

func TestPoamOverdueTransitionScannerWorker_TransitionsInProgressItemsToOverdue(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(-1 * 24 * time.Hour) // yesterday

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusInProgress, &deadline, "poc@example.com")

	w := NewPoamOverdueTransitionScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[PoamOverdueTransitionScannerArgs]{})
	require.NoError(t, err)

	var updated poamrel.PoamItem
	require.NoError(t, db.First(&updated, "id = ?", item.ID).Error)
	assert.Equal(t, string(poamrel.PoamItemStatusOverdue), updated.Status)
}

func TestPoamOverdueTransitionScannerWorker_SkipsFutureDeadlines(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(10 * 24 * time.Hour) // 10 days from now

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusOpen, &deadline, "poc@example.com")

	w := NewPoamOverdueTransitionScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[PoamOverdueTransitionScannerArgs]{})
	require.NoError(t, err)

	var unchanged poamrel.PoamItem
	require.NoError(t, db.First(&unchanged, "id = ?", item.ID).Error)
	assert.Equal(t, string(poamrel.PoamItemStatusOpen), unchanged.Status, "expected status to remain open")
	assert.Empty(t, client.params, "expected no notification jobs for non-overdue items")
}

func TestPoamOverdueTransitionScannerWorker_IdempotentOnAlreadyOverdueItems(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(-5 * 24 * time.Hour)

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusOverdue, &deadline, "poc@example.com")

	w := NewPoamOverdueTransitionScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[PoamOverdueTransitionScannerArgs]{})
	require.NoError(t, err)

	// Already-overdue items should not be re-processed
	assert.Empty(t, client.params, "expected no jobs for already-overdue items")

	var unchanged poamrel.PoamItem
	require.NoError(t, db.First(&unchanged, "id = ?", item.ID).Error)
	assert.Equal(t, string(poamrel.PoamItemStatusOverdue), unchanged.Status)
}

// ---------------------------------------------------------------------------
// Milestone Overdue Scanner tests
// ---------------------------------------------------------------------------

func TestMilestoneOverdueScannerWorker_EnqueuesForOverduePlannedMilestones(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(30 * 24 * time.Hour) // POAM item itself is not overdue
	mileDue := now.Add(-3 * 24 * time.Hour)  // milestone due 3 days ago

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusInProgress, &deadline, "poc@example.com")
	milestone := createTestPoamMilestone(t, db, item.ID, string(poamrel.MilestoneStatusOpen), &mileDue)

	w := NewMilestoneOverdueScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[MilestoneOverdueScannerArgs]{})
	require.NoError(t, err)

	require.NotEmpty(t, client.params, "expected at least one milestone reminder job")
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(MilestoneOverdueReminderArgs); ok {
			if args.MilestoneID == milestone.ID {
				found = true
				assert.Equal(t, item.ID, args.PoamItemID)
			}
		}
	}
	assert.True(t, found, "expected a MilestoneOverdueReminderArgs job for the overdue milestone")
}

func TestMilestoneOverdueScannerWorker_SkipsMilestonesWithFutureDueDate(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(30 * 24 * time.Hour)
	mileDue := now.Add(7 * 24 * time.Hour) // due in 7 days — not overdue

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusInProgress, &deadline, "poc@example.com")
	createTestPoamMilestone(t, db, item.ID, string(poamrel.MilestoneStatusOpen), &mileDue)

	w := NewMilestoneOverdueScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[MilestoneOverdueScannerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no jobs for milestones with future due dates")
}

func TestMilestoneOverdueScannerWorker_SkipsMilestonesOnCompletedParent(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(30 * 24 * time.Hour)
	mileDue := now.Add(-2 * 24 * time.Hour) // overdue milestone

	// Parent POAM item is completed — milestone should be skipped
	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusCompleted, &deadline, "poc@example.com")
	createTestPoamMilestone(t, db, item.ID, string(poamrel.MilestoneStatusOpen), &mileDue)

	w := NewMilestoneOverdueScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[MilestoneOverdueScannerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no jobs for milestones on completed POAM items")
}

func TestMilestoneOverdueScannerWorker_SkipsCompletedMilestones(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	now := time.Now().UTC()
	deadline := now.Add(30 * 24 * time.Hour)
	mileDue := now.Add(-2 * 24 * time.Hour)

	item, _ := createTestPoamItem(t, db, poamrel.PoamItemStatusInProgress, &deadline, "poc@example.com")
	// completed milestone — should not be re-reminded
	createTestPoamMilestone(t, db, item.ID, string(poamrel.MilestoneStatusCompleted), &mileDue)

	w := NewMilestoneOverdueScannerWorker(db, client, &stubUserRepository{}, "http://localhost", logger)
	err := w.Work(context.Background(), &river.Job[MilestoneOverdueScannerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no jobs for completed milestones")
}
