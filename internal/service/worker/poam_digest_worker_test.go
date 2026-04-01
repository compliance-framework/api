package worker

// poam_digest_worker_test.go — unit tests for the POAM open digest grouping logic.
//
// Tests exercise the classification predicates and classifyPoamDigest function
// in isolation using in-memory data, without requiring a database or River client.
// A separate integration-level test (TestPoamOpenDigestSchedulerWorker_*) uses
// the in-memory SQLite DB to exercise the full scheduler → worker pipeline.

import (
	"context"
	"testing"
	"time"

	poamrel "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func makePoamItem(status poamrel.PoamItemStatus, createdAt time.Time, updatedAt time.Time, deadline *time.Time) poamrel.PoamItem {
	ownerID := uuid.New()
	return poamrel.PoamItem{
		ID:                    uuid.New(),
		SspID:                 uuid.New(),
		Title:                 "Test POAM",
		Status:                string(status),
		PrimaryOwnerUserID:    &ownerID,
		PlannedCompletionDate: deadline,
		Milestones:            []poamrel.PoamItemMilestone{},
	}
}

func makePoamItemWithTimes(status poamrel.PoamItemStatus, createdAt time.Time, updatedAt time.Time, deadline *time.Time) poamrel.PoamItem {
	item := makePoamItem(status, createdAt, updatedAt, deadline)
	// Manually set CreatedAt/UpdatedAt for classification tests.
	// GORM normally sets these; we set them directly for unit tests.
	item.CreatedAt = createdAt
	item.UpdatedAt = updatedAt
	return item
}

func makeMilestone(status poamrel.MilestoneStatus, dueDate *time.Time) poamrel.PoamItemMilestone {
	return poamrel.PoamItemMilestone{
		ID:                    uuid.New(),
		PoamItemID:            uuid.New(),
		Title:                 "Test Milestone",
		Status:                string(status),
		PlannedCompletionDate: dueDate,
	}
}

// ─── isPoamNewSinceWindow ─────────────────────────────────────────────────────

func TestIsPoamNewSinceWindow_NewItemWithinWindow(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}
	// Created 12 hours ago — within the window
	createdAt := now.Add(-12 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, createdAt, createdAt, nil)
	assert.True(t, isPoamNewSinceWindow(&item, window), "item created within window should be classified as new")
}

func TestIsPoamNewSinceWindow_OldItemOutsideWindow(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}
	// Created 48 hours ago — outside the window
	createdAt := now.Add(-48 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, createdAt, createdAt, nil)
	assert.False(t, isPoamNewSinceWindow(&item, window), "item created before window start should not be classified as new")
}

func TestIsPoamNewSinceWindow_InactiveStatusExcluded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}
	createdAt := now.Add(-6 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusCompleted, createdAt, createdAt, nil)
	assert.False(t, isPoamNewSinceWindow(&item, window), "completed items should not appear in new-since-window bucket")
}

// ─── isPoamOverdue ────────────────────────────────────────────────────────────

func TestIsPoamOverdue_OverdueStatus(t *testing.T) {
	item := makePoamItem(poamrel.PoamItemStatusOverdue, time.Now(), time.Now(), nil)
	assert.True(t, isPoamOverdue(&item))
}

func TestIsPoamOverdue_OpenStatus(t *testing.T) {
	item := makePoamItem(poamrel.PoamItemStatusOpen, time.Now(), time.Now(), nil)
	assert.False(t, isPoamOverdue(&item))
}

// ─── isPoamApproachingDeadline ────────────────────────────────────────────────

func TestIsPoamApproachingDeadline_DeadlineIn20Days(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(20 * 24 * time.Hour)
	item := makePoamItem(poamrel.PoamItemStatusOpen, now, now, &deadline)
	assert.True(t, isPoamApproachingDeadline(&item, now), "deadline 20 days out should be approaching")
}

func TestIsPoamApproachingDeadline_DeadlineIn45Days(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(45 * 24 * time.Hour)
	item := makePoamItem(poamrel.PoamItemStatusOpen, now, now, &deadline)
	assert.False(t, isPoamApproachingDeadline(&item, now), "deadline 45 days out should not be approaching")
}

func TestIsPoamApproachingDeadline_OverdueStatusExcluded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(5 * 24 * time.Hour)
	item := makePoamItem(poamrel.PoamItemStatusOverdue, now, now, &deadline)
	assert.False(t, isPoamApproachingDeadline(&item, now), "overdue items should not appear in approaching deadline bucket")
}

func TestIsPoamApproachingDeadline_CompletedStatusExcluded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(5 * 24 * time.Hour)
	item := makePoamItem(poamrel.PoamItemStatusCompleted, now, now, &deadline)
	assert.False(t, isPoamApproachingDeadline(&item, now), "completed items should not appear in approaching deadline bucket")
}

func TestIsPoamApproachingDeadline_NoDeadline(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	item := makePoamItem(poamrel.PoamItemStatusOpen, now, now, nil)
	assert.False(t, isPoamApproachingDeadline(&item, now), "items without deadline should not appear in approaching deadline bucket")
}

func TestIsPoamApproachingDeadline_PastDeadline(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(-1 * 24 * time.Hour) // yesterday
	item := makePoamItem(poamrel.PoamItemStatusOpen, now, now, &deadline)
	assert.False(t, isPoamApproachingDeadline(&item, now), "past deadline should not appear in approaching deadline bucket")
}

// ─── isPoamStale ──────────────────────────────────────────────────────────────

func TestIsPoamStale_OpenItemNotUpdatedIn35Days(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	oldTime := now.Add(-35 * 24 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, oldTime, oldTime, nil)
	assert.True(t, isPoamStale(&item, now), "open item not updated in 35 days should be stale")
}

func TestIsPoamStale_OpenItemUpdatedRecently(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	recentTime := now.Add(-10 * 24 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, recentTime, recentTime, nil)
	assert.False(t, isPoamStale(&item, now), "open item updated 10 days ago should not be stale")
}

func TestIsPoamStale_InProgressItemExcluded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	oldTime := now.Add(-40 * 24 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusInProgress, oldTime, oldTime, nil)
	assert.False(t, isPoamStale(&item, now), "in-progress items should not appear in stale bucket")
}

func TestIsPoamStale_OverdueItemExcluded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	oldTime := now.Add(-40 * 24 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOverdue, oldTime, oldTime, nil)
	assert.False(t, isPoamStale(&item, now), "overdue items should not appear in stale bucket (they appear in overdue bucket)")
}

func TestIsPoamStale_BoundaryExactly30Days(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	// Exactly 30 days ago — should be stale (boundary is inclusive: !lastUpdate.After(now - 30d))
	exactlyAt := now.Add(-30 * 24 * time.Hour)
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, exactlyAt, exactlyAt, nil)
	assert.True(t, isPoamStale(&item, now), "item exactly at 30-day boundary should be stale")
}

// ─── isMilestoneDueSoon ───────────────────────────────────────────────────────

func TestIsMilestoneDueSoon_DueIn7Days(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	dueDate := now.Add(7 * 24 * time.Hour)
	ms := makeMilestone(poamrel.MilestoneStatusOpen, &dueDate)
	assert.True(t, isMilestoneDueSoon(&ms, now), "milestone due in 7 days should be due soon")
}

func TestIsMilestoneDueSoon_DueIn20Days(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	dueDate := now.Add(20 * 24 * time.Hour)
	ms := makeMilestone(poamrel.MilestoneStatusOpen, &dueDate)
	assert.False(t, isMilestoneDueSoon(&ms, now), "milestone due in 20 days should not be due soon (horizon is 14 days)")
}

func TestIsMilestoneDueSoon_CompletedMilestoneExcluded(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	dueDate := now.Add(5 * 24 * time.Hour)
	ms := makeMilestone(poamrel.MilestoneStatusCompleted, &dueDate)
	assert.False(t, isMilestoneDueSoon(&ms, now), "completed milestones should not appear in due-soon bucket")
}

func TestIsMilestoneDueSoon_NoDueDate(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	ms := makeMilestone(poamrel.MilestoneStatusOpen, nil)
	assert.False(t, isMilestoneDueSoon(&ms, now), "milestones without due date should not appear in due-soon bucket")
}

func TestIsMilestoneDueSoon_PastDueDate(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	dueDate := now.Add(-1 * 24 * time.Hour) // yesterday
	ms := makeMilestone(poamrel.MilestoneStatusOpen, &dueDate)
	assert.False(t, isMilestoneDueSoon(&ms, now), "past-due milestones should not appear in due-soon bucket (they are overdue)")
}

// ─── classifyPoamDigest ───────────────────────────────────────────────────────

func TestClassifyPoamDigest_AllFiveBuckets(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}

	// 1. New item (created 6 hours ago, open)
	newItem := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, now.Add(-6*time.Hour), now.Add(-6*time.Hour), nil)

	// 2. Overdue item
	overdueItem := makePoamItemWithTimes(poamrel.PoamItemStatusOverdue, now.Add(-60*24*time.Hour), now.Add(-60*24*time.Hour), nil)

	// 3. Approaching deadline (20 days out)
	approachDeadline := now.Add(20 * 24 * time.Hour)
	approachItem := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, now.Add(-10*24*time.Hour), now.Add(-10*24*time.Hour), &approachDeadline)

	// 4. Stale item (open, not updated in 35 days)
	staleItem := makePoamItemWithTimes(poamrel.PoamItemStatusOpen, now.Add(-35*24*time.Hour), now.Add(-35*24*time.Hour), nil)

	// 5. Item with milestone due soon (7 days)
	milestoneDue := now.Add(7 * 24 * time.Hour)
	milestoneItem := makePoamItemWithTimes(poamrel.PoamItemStatusInProgress, now.Add(-5*24*time.Hour), now.Add(-5*24*time.Hour), nil)
	milestoneItem.Milestones = []poamrel.PoamItemMilestone{
		makeMilestone(poamrel.MilestoneStatusOpen, &milestoneDue),
	}

	items := []poamrel.PoamItem{newItem, overdueItem, approachItem, staleItem, milestoneItem}
	sspNames := make(map[uuid.UUID]string)
	for _, item := range items {
		sspNames[item.SspID] = "Test SSP"
	}

	c := classifyPoamDigest(items, sspNames, "http://localhost", now, window)

	assert.Len(t, c.NewSinceLastDigest, 1, "expected 1 new item")
	assert.Len(t, c.Overdue, 1, "expected 1 overdue item")
	assert.Len(t, c.ApproachingDeadline, 1, "expected 1 approaching deadline item")
	assert.Len(t, c.Stale, 1, "expected 1 stale item")
	assert.Len(t, c.MilestonesDueSoon, 1, "expected 1 milestone due soon")
	assert.False(t, c.Empty(), "classification should not be empty")
}

func TestClassifyPoamDigest_EmptyWhenNoItems(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}
	c := classifyPoamDigest([]poamrel.PoamItem{}, map[uuid.UUID]string{}, "http://localhost", now, window)
	assert.True(t, c.Empty(), "classification should be empty when no items are provided")
}

func TestClassifyPoamDigest_ItemCanAppearInMultipleBuckets(t *testing.T) {
	// An overdue item that was also created within the window should appear in both
	// the new-since-last-digest bucket AND the overdue bucket.
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}
	// Created 6 hours ago, already marked overdue
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOverdue, now.Add(-6*time.Hour), now.Add(-6*time.Hour), nil)
	sspNames := map[uuid.UUID]string{item.SspID: "Test SSP"}

	c := classifyPoamDigest([]poamrel.PoamItem{item}, sspNames, "http://localhost", now, window)

	assert.Len(t, c.NewSinceLastDigest, 1, "overdue item created within window should also appear in new bucket")
	assert.Len(t, c.Overdue, 1, "overdue item should appear in overdue bucket")
}

func TestClassifyPoamDigest_PoamURLFormatted(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	window := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: now.Add(-24 * time.Hour),
		End:   now,
	}
	item := makePoamItemWithTimes(poamrel.PoamItemStatusOverdue, now.Add(-6*time.Hour), now.Add(-6*time.Hour), nil)
	sspNames := map[uuid.UUID]string{item.SspID: "Test SSP"}

	c := classifyPoamDigest([]poamrel.PoamItem{item}, sspNames, "https://app.example.com/", now, window)

	require.Len(t, c.Overdue, 1)
	expectedURL := "https://app.example.com/poam-items/" + item.ID.String()
	assert.Equal(t, expectedURL, c.Overdue[0].PoamURL, "POAM URL should be correctly formatted with trailing slash stripped")
}

// ─── computePoamDigestWindow ──────────────────────────────────────────────────

func TestComputePoamDigestWindow_Daily(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	w, err := computePoamDigestWindow(now, poamDigestWindowDaily)
	require.NoError(t, err)
	assert.Equal(t, poamDigestWindowDaily, w.Kind)
	assert.Equal(t, poamDigestDailyPeriod, w.ByPeriod)
	// End should be start of today
	assert.Equal(t, startOfDayUTC(now), w.End)
	// Start should be 24h before end
	assert.Equal(t, w.End.Add(-poamDigestDailyPeriod), w.Start)
}

func TestComputePoamDigestWindow_Weekly(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	w, err := computePoamDigestWindow(now, poamDigestWindowWeekly)
	require.NoError(t, err)
	assert.Equal(t, poamDigestWindowWeekly, w.Kind)
	assert.Equal(t, poamDigestWeeklyPeriod, w.ByPeriod)
}

func TestComputePoamDigestWindow_UnknownKindReturnsError(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	_, err := computePoamDigestWindow(now, "monthly")
	assert.Error(t, err, "unknown window kind should return an error")
}

// ─── formatPoamDigestPeriodLabel ─────────────────────────────────────────────

func TestFormatPoamDigestPeriodLabel_Daily(t *testing.T) {
	w := poamDigestWindow{
		Kind:  poamDigestWindowDaily,
		Start: time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}
	label := formatPoamDigestPeriodLabel(w)
	assert.Contains(t, label, "31 Mar 2026", "daily label should contain the start date")
}

func TestFormatPoamDigestPeriodLabel_Weekly(t *testing.T) {
	w := poamDigestWindow{
		Kind:  poamDigestWindowWeekly,
		Start: time.Date(2026, 3, 25, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	}
	label := formatPoamDigestPeriodLabel(w)
	assert.Contains(t, label, "Weekly digest", "weekly label should contain 'Weekly digest'")
}

// ─── PoamOpenDigestSchedulerWorker — DB-level unit tests ─────────────────────

func TestPoamOpenDigestSchedulerWorker_EnqueuesPerRecipient(t *testing.T) {
	db := newPoamWorkersTestDB(t) // uses SQLite in-memory with POAM tables migrated
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	// Create two POAM items with different owners
	_, ownerA := createTestPoamItem(t, db, poamrel.PoamItemStatusOpen, nil, "ownerA@example.com")
	_, ownerB := createTestPoamItem(t, db, poamrel.PoamItemStatusInProgress, nil, "ownerB@example.com")

	w := NewPoamOpenDigestSchedulerWorker(db, client, poamDigestWindowDaily, logger)
	err := w.Work(context.Background(), &river.Job[PoamOpenDigestSchedulerArgs]{})
	require.NoError(t, err)

	// Should enqueue exactly one digest job per unique recipient
	recipientIDs := map[uuid.UUID]bool{}
	for _, p := range client.params {
		if args, ok := p.Args.(PoamOpenDigestArgs); ok {
			recipientIDs[args.RecipientUserID] = true
		}
	}
	assert.True(t, recipientIDs[ownerA], "expected a digest job for ownerA")
	assert.True(t, recipientIDs[ownerB], "expected a digest job for ownerB")
	assert.Len(t, recipientIDs, 2, "expected exactly 2 unique recipients")
}

func TestPoamOpenDigestSchedulerWorker_SkipsCompletedItems(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	// Only completed items — should produce no digest jobs
	createTestPoamItem(t, db, poamrel.PoamItemStatusCompleted, nil, "owner@example.com")

	w := NewPoamOpenDigestSchedulerWorker(db, client, poamDigestWindowDaily, logger)
	err := w.Work(context.Background(), &river.Job[PoamOpenDigestSchedulerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no digest jobs when only completed items exist")
}

func TestPoamOpenDigestSchedulerWorker_NoItemsNoJobs(t *testing.T) {
	db := newPoamWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()

	w := NewPoamOpenDigestSchedulerWorker(db, client, poamDigestWindowDaily, logger)
	err := w.Work(context.Background(), &river.Job[PoamOpenDigestSchedulerArgs]{})
	require.NoError(t, err)
	assert.Empty(t, client.params, "expected no jobs when no POAM items exist")
}
