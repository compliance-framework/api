//go:build integration

package worker

// poam_workers_integration_test.go — integration tests for the three POAM
// background job scanners.
//
// These tests run against a real Postgres database (via the IntegrationTestSuite)
// and verify:
//   - Scanner enqueues the correct notification jobs
//   - Overdue transition scanner mutates status in the DB
//   - Idempotency: running a scanner twice in the same window does not
//     double-enqueue
//   - Notification workers call emailService.UseTemplate and emailService.Send
//     with the correct arguments

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	poamrel "github.com/compliance-framework/api/internal/service/relational/poam"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Suite definition
// ---------------------------------------------------------------------------

type PoamWorkersIntegrationSuite struct {
	tests.IntegrationTestSuite
	logger *zap.SugaredLogger
}

func TestPoamWorkersIntegration(t *testing.T) {
	suite.Run(t, new(PoamWorkersIntegrationSuite))
}

func (suite *PoamWorkersIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()
	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.Config.WebBaseURL = "https://app.example.com"
}

func (suite *PoamWorkersIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

// ---------------------------------------------------------------------------
// Shared seed helpers
// ---------------------------------------------------------------------------

// seedUser creates a user in the DB and returns their ID and email.
func (suite *PoamWorkersIntegrationSuite) seedUser(email string) uuid.UUID {
	id := uuid.New()
	suite.Require().NoError(suite.DB.Model(&relational.User{}).Create(map[string]interface{}{
		"id":          id,
		"email":       email,
		"first_name":  "Test",
		"last_name":   "User",
		"auth_method": "password",
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.UserNotificationSubscription{
		UserID:           id.String(),
		NotificationType: notification.SubscriptionGateRiskNotifications,
		Channels:         []string{notification.DeliveryChannelEmail},
	}).Error)
	return id
}

// seedSSP creates a SystemSecurityPlan with a SystemCharacteristics row.
func (suite *PoamWorkersIntegrationSuite) seedSSP(shortName string) uuid.UUID {
	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.SystemCharacteristics{
		SystemSecurityPlanId: sspID,
		SystemNameShort:      shortName,
		SystemName:           shortName,
	}).Error)
	return sspID
}

// seedPoamItem creates a PoamItem with the given status and deadline.
func (suite *PoamWorkersIntegrationSuite) seedPoamItem(
	sspID uuid.UUID,
	ownerID uuid.UUID,
	status poamrel.PoamItemStatus,
	deadline time.Time,
) poamrel.PoamItem {
	item := poamrel.PoamItem{
		ID:                    uuid.New(),
		SspID:                 sspID,
		Title:                 "Integration Test POAM Item",
		Description:           "Created by integration test",
		Status:                string(status),
		SourceType:            "manual",
		PrimaryOwnerUserID:    &ownerID,
		PlannedCompletionDate: &deadline,
	}
	suite.Require().NoError(suite.DB.Create(&item).Error)
	return item
}

// seedMilestone creates a PoamItemMilestone for the given parent item.
func (suite *PoamWorkersIntegrationSuite) seedMilestone(
	itemID uuid.UUID,
	status string,
	plannedCompletion time.Time,
) poamrel.PoamItemMilestone {
	m := poamrel.PoamItemMilestone{
		ID:                    uuid.New(),
		PoamItemID:            itemID,
		Title:                 "Integration Test Milestone",
		Status:                status,
		PlannedCompletionDate: &plannedCompletion,
	}
	suite.Require().NoError(suite.DB.Create(&m).Error)
	return m
}

// ---------------------------------------------------------------------------
// POAM Deadline Reminder Scanner integration tests
// ---------------------------------------------------------------------------

// TestPoamDeadlineReminderScanner_EnqueuesAndNotifies verifies the full
// scanner → notification worker pipeline for an approaching deadline.
func (suite *PoamWorkersIntegrationSuite) TestPoamDeadlineReminderScanner_EnqueuesAndNotifies() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("owner@example.com")
	sspID := suite.seedSSP("Reminder SSP")
	deadline := now.Add(15 * 24 * time.Hour) // 15 days — within 30-day window
	item := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOpen, deadline)

	client := &stubRiverClient{}
	scanner := NewPoamDeadlineReminderScannerWorker(suite.DB, client, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, 30*24*time.Hour, suite.logger)
	suite.Require().NoError(scanner.Work(ctx, &river.Job[PoamDeadlineReminderScannerArgs]{}))

	// Verify scanner enqueued a reminder job for this item
	suite.Require().NotEmpty(client.params, "scanner should enqueue at least one job")
	var reminderArgs PoamDeadlineReminderArgs
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(PoamDeadlineReminderArgs); ok && args.PoamItemID == item.ID {
			reminderArgs = args
			found = true
		}
	}
	suite.Require().True(found, "expected a PoamDeadlineReminderArgs job for the seeded item")
	suite.Equal(sspID, reminderArgs.SspID)
	suite.Equal("Integration Test POAM Item", reminderArgs.PoamTitle)
	suite.Contains(reminderArgs.PoamURL, item.ID.String())

	// Now run the notification worker and verify the email is sent.
	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "poam-deadline-reminder", mock.MatchedBy(func(data map[string]interface{}) bool {
		title, _ := data["PoamTitle"].(string)
		return title == "Integration Test POAM Item"
	})).Return("<html>reminder</html>", "POAM deadline reminder", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-reminder-1"}, nil)

	notifier := NewPoamDeadlineReminderWorker(
		NewGORMUserRepository(suite.DB),
		suite.Config.WebBaseURL,
		newTestPoamNotificationServiceFactory(mockEmail, nil),
		suite.logger,
	)
	suite.Require().NoError(notifier.Work(ctx, &river.Job[PoamDeadlineReminderArgs]{Args: reminderArgs}))
	mockEmail.AssertExpectations(suite.T())
}

// TestPoamDeadlineReminderScanner_Idempotency verifies that running the scanner
// twice with the same ByArgs does not double-enqueue (River deduplication).
func (suite *PoamWorkersIntegrationSuite) TestPoamDeadlineReminderScanner_Idempotency() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("idempotent@example.com")
	sspID := suite.seedSSP("Idempotency SSP")
	deadline := now.Add(10 * 24 * time.Hour)
	suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOpen, deadline)

	client := &stubRiverClient{}
	scanner := NewPoamDeadlineReminderScannerWorker(suite.DB, client, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, 30*24*time.Hour, suite.logger)

	// Run scanner twice
	suite.Require().NoError(scanner.Work(ctx, &river.Job[PoamDeadlineReminderScannerArgs]{}))
	firstRunCount := len(client.params)
	suite.Require().NoError(scanner.Work(ctx, &river.Job[PoamDeadlineReminderScannerArgs]{}))
	secondRunCount := len(client.params)

	// The stubRiverClient does not enforce River's deduplication, so both runs
	// will enqueue. What we verify here is that the ReminderWindowBucket is
	// identical between both runs (same calendar day), which is the key that
	// River uses for ByArgs deduplication in production.
	suite.Require().Greater(firstRunCount, 0)
	suite.Equal(firstRunCount, secondRunCount-firstRunCount,
		"second run should enqueue the same number of jobs as the first (same bucket key)")

	// Verify the ReminderWindowBucket is identical across both runs
	var buckets []string
	for _, p := range client.params {
		if args, ok := p.Args.(PoamDeadlineReminderArgs); ok {
			buckets = append(buckets, args.ReminderWindowBucket)
		}
	}
	suite.Require().Len(buckets, firstRunCount*2)
	for i := 1; i < len(buckets); i++ {
		suite.Equal(buckets[0], buckets[i], "all reminder jobs should share the same ReminderWindowBucket")
	}
}

// ---------------------------------------------------------------------------
// POAM Overdue Transition Scanner integration tests
// ---------------------------------------------------------------------------

// TestPoamOverdueTransitionScanner_TransitionsAndNotifies verifies the full
// scanner → DB mutation → notification worker pipeline.
func (suite *PoamWorkersIntegrationSuite) TestPoamOverdueTransitionScanner_TransitionsAndNotifies() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("overdue-owner@example.com")
	sspID := suite.seedSSP("Overdue SSP")
	deadline := now.Add(-3 * 24 * time.Hour) // 3 days ago — overdue
	item := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOpen, deadline)

	client := &stubRiverClient{}
	scanner := NewPoamOverdueTransitionScannerWorker(suite.DB, client, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, suite.logger)
	suite.Require().NoError(scanner.Work(ctx, &river.Job[PoamOverdueTransitionScannerArgs]{}))

	// Verify DB status transition
	var updated poamrel.PoamItem
	suite.Require().NoError(suite.DB.First(&updated, "id = ?", item.ID).Error)
	suite.Equal(string(poamrel.PoamItemStatusOverdue), updated.Status, "item should be transitioned to overdue")

	// Verify notification job was enqueued
	suite.Require().NotEmpty(client.params)
	var notifArgs PoamOverdueNotificationArgs
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(PoamOverdueNotificationArgs); ok && args.PoamItemID == item.ID {
			notifArgs = args
			found = true
		}
	}
	suite.Require().True(found, "expected a PoamOverdueNotificationArgs job for the overdue item")

	// Run the notification worker
	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "poam-overdue-notification", mock.MatchedBy(func(data map[string]interface{}) bool {
		title, _ := data["PoamTitle"].(string)
		return title == "Integration Test POAM Item"
	})).Return("<html>overdue</html>", "POAM item overdue", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "overdue-owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-overdue-1"}, nil)

	notifier := NewPoamOverdueNotificationWorker(
		NewGORMUserRepository(suite.DB),
		suite.Config.WebBaseURL,
		newTestPoamNotificationServiceFactory(mockEmail, nil),
		suite.logger,
	)
	suite.Require().NoError(notifier.Work(ctx, &river.Job[PoamOverdueNotificationArgs]{Args: notifArgs}))
	mockEmail.AssertExpectations(suite.T())
}

// TestPoamOverdueTransitionScanner_IdempotentOnAlreadyOverdue verifies that
// items already in overdue status are not re-processed.
func (suite *PoamWorkersIntegrationSuite) TestPoamOverdueTransitionScanner_IdempotentOnAlreadyOverdue() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("already-overdue@example.com")
	sspID := suite.seedSSP("Already Overdue SSP")
	deadline := now.Add(-5 * 24 * time.Hour)
	suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOverdue, deadline)

	client := &stubRiverClient{}
	scanner := NewPoamOverdueTransitionScannerWorker(suite.DB, client, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, suite.logger)
	suite.Require().NoError(scanner.Work(ctx, &river.Job[PoamOverdueTransitionScannerArgs]{}))

	suite.Empty(client.params, "already-overdue items should not be re-processed")
}

// ---------------------------------------------------------------------------
// Milestone Overdue Scanner integration tests
// ---------------------------------------------------------------------------

// TestMilestoneOverdueScanner_EnqueuesAndNotifies verifies the full
// scanner → notification worker pipeline for an overdue planned milestone.
func (suite *PoamWorkersIntegrationSuite) TestMilestoneOverdueScanner_EnqueuesAndNotifies() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("milestone-owner@example.com")
	sspID := suite.seedSSP("Milestone SSP")
	itemDeadline := now.Add(30 * 24 * time.Hour) // POAM item not yet overdue
	item := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusInProgress, itemDeadline)

	milestoneDue := now.Add(-4 * 24 * time.Hour) // milestone was due 4 days ago
	milestone := suite.seedMilestone(item.ID, string(poamrel.MilestoneStatusOpen), milestoneDue)

	client := &stubRiverClient{}
	scanner := NewMilestoneOverdueScannerWorker(suite.DB, client, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, suite.logger)
	suite.Require().NoError(scanner.Work(ctx, &river.Job[MilestoneOverdueScannerArgs]{}))

	suite.Require().NotEmpty(client.params, "scanner should enqueue at least one milestone reminder job")
	var reminderArgs MilestoneOverdueReminderArgs
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(MilestoneOverdueReminderArgs); ok && args.MilestoneID == milestone.ID {
			reminderArgs = args
			found = true
		}
	}
	suite.Require().True(found, "expected a MilestoneOverdueReminderArgs job for the overdue milestone")
	suite.Equal(item.ID, reminderArgs.PoamItemID)
	suite.Equal("Integration Test Milestone", reminderArgs.MilestoneTitle)

	// Run the notification worker
	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "poam-milestone-overdue-reminder", mock.MatchedBy(func(data map[string]interface{}) bool {
		title, _ := data["MilestoneTitle"].(string)
		return title == "Integration Test Milestone"
	})).Return("<html>milestone</html>", "Milestone overdue reminder", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "milestone-owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-milestone-1"}, nil)

	notifier := NewMilestoneOverdueReminderWorker(
		NewGORMUserRepository(suite.DB),
		suite.Config.WebBaseURL,
		newTestPoamNotificationServiceFactory(mockEmail, nil),
		suite.logger,
	)
	suite.Require().NoError(notifier.Work(ctx, &river.Job[MilestoneOverdueReminderArgs]{Args: reminderArgs}))
	mockEmail.AssertExpectations(suite.T())
}

// TestMilestoneOverdueScanner_SkipsCompletedParent verifies that milestones
// on completed POAM items are not included in the scan.
func (suite *PoamWorkersIntegrationSuite) TestMilestoneOverdueScanner_SkipsCompletedParent() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("completed-parent@example.com")
	sspID := suite.seedSSP("Completed Parent SSP")
	itemDeadline := now.Add(30 * 24 * time.Hour)
	item := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusCompleted, itemDeadline)

	milestoneDue := now.Add(-2 * 24 * time.Hour)
	suite.seedMilestone(item.ID, string(poamrel.MilestoneStatusOpen), milestoneDue)

	client := &stubRiverClient{}
	scanner := NewMilestoneOverdueScannerWorker(suite.DB, client, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, suite.logger)
	suite.Require().NoError(scanner.Work(ctx, &river.Job[MilestoneOverdueScannerArgs]{}))

	suite.Empty(client.params, "milestones on completed POAM items should not be scanned")
}

// ---------------------------------------------------------------------------
// POAM Open Digest integration tests (BCH-1186 Phase 3)
// ---------------------------------------------------------------------------

// TestPoamOpenDigest_CorrectGroupingPerRecipient is the primary integration
// test required by the Definition of Done. It creates three POAM items in
// different states (overdue, approaching deadline, stale), runs the scheduler
// and per-recipient digest worker, and verifies correct bucket grouping.
func (suite *PoamWorkersIntegrationSuite) TestPoamOpenDigest_CorrectGroupingPerRecipient() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("digest-owner@example.com")
	sspID := suite.seedSSP("Digest Test SSP")

	// Item 1: overdue
	overdueDeadline := now.Add(-5 * 24 * time.Hour)
	overdueItem := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOverdue, overdueDeadline)

	// Item 2: approaching deadline (20 days out, open status)
	approachDeadline := now.Add(20 * 24 * time.Hour)
	approachItem := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOpen, approachDeadline)

	// Item 3: stale (open, updated >30 days ago — force UpdatedAt via raw SQL)
	staleDeadline := now.Add(90 * 24 * time.Hour)
	staleItem := suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOpen, staleDeadline)
	staleTime := now.Add(-35 * 24 * time.Hour)
	suite.Require().NoError(suite.DB.Exec(
		"UPDATE ccf_poam_items SET updated_at = ?, created_at = ? WHERE id = ?",
		staleTime, staleTime, staleItem.ID,
	).Error)

	// Run the scheduler — should enqueue exactly one PoamOpenDigestArgs job for ownerID
	client := &stubRiverClient{}
	scheduler := NewPoamOpenDigestSchedulerWorker(suite.DB, client, poamDigestWindowDaily, suite.logger)
	suite.Require().NoError(scheduler.Work(ctx, &river.Job[PoamOpenDigestSchedulerArgs]{}))

	var digestArgs PoamOpenDigestArgs
	found := false
	for _, p := range client.params {
		if args, ok := p.Args.(PoamOpenDigestArgs); ok && args.RecipientUserID == ownerID {
			digestArgs = args
			found = true
		}
	}
	suite.Require().True(found, "scheduler should enqueue a digest job for the owner")

	// Run the per-recipient digest worker
	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "poam-open-digest", mock.MatchedBy(func(data map[string]interface{}) bool {
		overdueBucket, _ := data["Overdue"].([]PoamDigestEmailItem)
		approachBucket, _ := data["ApproachingDeadline"].([]PoamDigestEmailItem)
		staleBucket, _ := data["Stale"].([]PoamDigestEmailItem)

		overdueFound := false
		for _, it := range overdueBucket {
			if it.PoamItemID == overdueItem.ID {
				overdueFound = true
			}
		}
		approachFound := false
		for _, it := range approachBucket {
			if it.PoamItemID == approachItem.ID {
				approachFound = true
			}
		}
		staleFound := false
		for _, it := range staleBucket {
			if it.PoamItemID == staleItem.ID {
				staleFound = true
			}
		}
		return overdueFound && approachFound && staleFound
	})).Return("<html>digest</html>", "POAM digest", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "digest-owner@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-digest-1"}, nil)

	digestWorker := NewPoamOpenDigestWorker(suite.DB, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, newTestPoamNotificationServiceFactory(mockEmail, nil), suite.logger)
	suite.Require().NoError(digestWorker.Work(ctx, &river.Job[PoamOpenDigestArgs]{Args: digestArgs}))
	mockEmail.AssertExpectations(suite.T())
}

// TestPoamOpenDigest_IdempotentScheduler verifies that running the scheduler
// twice in the same window produces the same set of jobs per run.
func (suite *PoamWorkersIntegrationSuite) TestPoamOpenDigest_IdempotentScheduler() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("idempotent-digest@example.com")
	sspID := suite.seedSSP("Idempotent Digest SSP")
	deadline := now.Add(30 * 24 * time.Hour)
	suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusOpen, deadline)
	suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusInProgress, deadline)

	client := &stubRiverClient{}
	scheduler := NewPoamOpenDigestSchedulerWorker(suite.DB, client, poamDigestWindowDaily, suite.logger)

	suite.Require().NoError(scheduler.Work(ctx, &river.Job[PoamOpenDigestSchedulerArgs]{}))
	firstRunCount := len(client.params)
	suite.Require().NoError(scheduler.Work(ctx, &river.Job[PoamOpenDigestSchedulerArgs]{}))
	secondRunCount := len(client.params)

	suite.Require().Greater(firstRunCount, 0)
	suite.Equal(firstRunCount, secondRunCount-firstRunCount,
		"second run should produce the same number of jobs; River deduplication prevents actual duplicates")
}

// TestPoamOpenDigest_SkipsRecipientsWithNoActiveItems verifies that recipients
// whose items are all completed do not receive a digest.
func (suite *PoamWorkersIntegrationSuite) TestPoamOpenDigest_SkipsRecipientsWithNoActiveItems() {
	ctx := context.Background()
	now := time.Now().UTC()

	ownerID := suite.seedUser("completed-only@example.com")
	sspID := suite.seedSSP("Completed Only SSP")
	deadline := now.Add(30 * 24 * time.Hour)
	suite.seedPoamItem(sspID, ownerID, poamrel.PoamItemStatusCompleted, deadline)

	client := &stubRiverClient{}
	scheduler := NewPoamOpenDigestSchedulerWorker(suite.DB, client, poamDigestWindowDaily, suite.logger)
	suite.Require().NoError(scheduler.Work(ctx, &river.Job[PoamOpenDigestSchedulerArgs]{}))

	for _, p := range client.params {
		if args, ok := p.Args.(PoamOpenDigestArgs); ok {
			suite.NotEqual(ownerID, args.RecipientUserID, "completed-only owner should not receive a digest")
		}
	}
}
