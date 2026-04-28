package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

func TestComputeRiskDigestWindow(t *testing.T) {
	now := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)

	daily, err := computeRiskDigestWindow(now, riskDigestWindowDaily)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC), daily.Start)
	assert.Equal(t, time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC), daily.End)
	assert.Equal(t, riskDigestDailyPeriod, daily.ByPeriod)

	weekly, err := computeRiskDigestWindow(now, riskDigestWindowWeekly)
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 3, 16, 0, 0, 0, 0, time.UTC), weekly.Start)
	assert.Equal(t, time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC), weekly.End)
	assert.Equal(t, riskDigestWeeklyPeriod, weekly.ByPeriod)
	assert.Equal(t, "16/mar/2026", weekly.PeriodTag)
}

func TestIsRiskOverdueForAction(t *testing.T) {
	now := time.Date(2026, 3, 23, 12, 0, 0, 0, time.UTC)
	risk := &riskrel.Risk{
		Status:    string(riskrel.RiskStatusOpen),
		CreatedAt: now.Add(-40 * 24 * time.Hour),
	}

	assert.True(t, isRiskOverdueForAction(risk, now, time.Time{}))
	assert.True(t, isRiskOverdueForAction(risk, now, risk.CreatedAt.Add(30*time.Second)))
	assert.False(t, isRiskOverdueForAction(risk, now, risk.CreatedAt.Add(2*time.Hour)))
}

func TestBuildRiskDigestEmailItem_SkipsNilRiskID(t *testing.T) {
	item, ok := buildRiskDigestEmailItem(&riskrel.Risk{
		Title:  "No ID risk",
		Status: string(riskrel.RiskStatusOpen),
	}, map[uuid.UUID]string{}, nil, nil, "https://app.example.com")

	assert.False(t, ok)
	assert.Empty(t, item)
}

func TestIsRiskNewSinceWindow_IncludesStartBoundary(t *testing.T) {
	window := riskDigestWindow{
		Start: time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC),
	}
	risk := &riskrel.Risk{
		Status:    string(riskrel.RiskStatusOpen),
		CreatedAt: window.Start,
	}

	assert.True(t, isRiskNewSinceWindow(risk, window))
	risk.CreatedAt = window.End
	assert.False(t, isRiskNewSinceWindow(risk, window))
}

func TestRiskOpenDigestSchedulerWorker_EnqueuesUniqueRecipients(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	client := &stubRiverClient{}
	logger := zap.NewNop().Sugar()
	now := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)

	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)

	ownerA := uuid.New()
	ownerB := uuid.New()
	riskID := uuid.New()
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:          relational.UUIDModel{ID: &riskID},
		Title:              "Digest candidate",
		Description:        "Scheduler coverage",
		Status:             string(riskrel.RiskStatusOpen),
		SSPID:              sspID,
		PrimaryOwnerUserID: &ownerA,
		SourceType:         string(riskrel.RiskSourceTypeManual),
		FirstSeenAt:        now.Add(-2 * time.Hour),
		LastSeenAt:         now.Add(-2 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&riskrel.RiskOwnerAssignment{
		RiskID:    riskID,
		OwnerKind: "user",
		OwnerRef:  ownerA.String(),
		IsPrimary: true,
	}).Error)
	require.NoError(t, db.Create(&riskrel.RiskOwnerAssignment{
		RiskID:    riskID,
		OwnerKind: "user",
		OwnerRef:  ownerB.String(),
		IsPrimary: false,
	}).Error)

	worker := NewRiskOpenDigestSchedulerWorker(db, client, riskDigestWindowDaily, logger)
	worker.now = func() time.Time { return now }

	err := worker.Work(context.Background(), &river.Job[RiskOpenDigestSchedulerArgs]{})
	require.NoError(t, err)
	require.Len(t, client.params, 2)

	argsA, ok := client.params[0].Args.(RiskOpenDigestArgs)
	require.True(t, ok)
	assert.Equal(t, riskDigestWindowDaily, argsA.WindowKind)
	assert.Equal(t, "2026-03-22T00:00:00Z", argsA.WindowStart)
	assert.Equal(t, "2026-03-23T00:00:00Z", argsA.WindowEnd)
	assert.Equal(t, "", argsA.Channel)
	assert.Equal(t, "digest", client.params[0].InsertOpts.Queue)
	assert.Equal(t, riskDigestDailyPeriod, client.params[0].InsertOpts.UniqueOpts.ByPeriod)

	gotRecipients := make([]uuid.UUID, 0, len(client.params))
	for _, param := range client.params {
		args := param.Args.(RiskOpenDigestArgs)
		gotRecipients = append(gotRecipients, args.RecipientUserID)
		assert.Equal(t, "", args.Channel)
	}
	assert.ElementsMatch(t, []uuid.UUID{ownerA, ownerB}, gotRecipients)
}

func TestRiskOpenDigestSchedulerWorker_WarnsOnInvalidRecipientUserID(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	client := &stubRiverClient{}
	now := time.Date(2026, 3, 23, 15, 0, 0, 0, time.UTC)
	core, observed := observer.New(zap.WarnLevel)
	logger := zap.New(core).Sugar()

	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)

	ownerID := uuid.New()
	riskID := uuid.New()
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:          relational.UUIDModel{ID: &riskID},
		Title:              "Digest candidate",
		Description:        "Scheduler coverage",
		Status:             string(riskrel.RiskStatusOpen),
		SSPID:              sspID,
		PrimaryOwnerUserID: &ownerID,
		SourceType:         string(riskrel.RiskSourceTypeManual),
		FirstSeenAt:        now.Add(-2 * time.Hour),
		LastSeenAt:         now.Add(-2 * time.Hour),
	}).Error)
	require.NoError(t, db.Create(&riskrel.RiskOwnerAssignment{
		RiskID:    riskID,
		OwnerKind: "user",
		OwnerRef:  "not-a-uuid",
		IsPrimary: false,
	}).Error)

	worker := NewRiskOpenDigestSchedulerWorker(db, client, riskDigestWindowDaily, logger)
	worker.now = func() time.Time { return now }

	err := worker.Work(context.Background(), &river.Job[RiskOpenDigestSchedulerArgs]{})
	require.NoError(t, err)
	require.Len(t, client.params, 1)
	for _, param := range client.params {
		require.Equal(t, ownerID, param.Args.(RiskOpenDigestArgs).RecipientUserID)
		require.Equal(t, "", param.Args.(RiskOpenDigestArgs).Channel)
	}

	logs := observed.FilterMessage("RiskOpenDigestSchedulerWorker: skipping invalid recipient user ID").All()
	require.Len(t, logs, 1)
	assert.Equal(t, "not-a-uuid", logs[0].ContextMap()["user_id"])
}

func TestRiskOpenDigestWorker_SendsGroupedDigest(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	now := time.Date(2026, 3, 23, 12, 0, 0, 0, time.UTC)
	windowStart := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC)

	recipientID := uuid.New()
	secondaryOwnerID := uuid.New()
	createTestUser(t, db, recipientID, true)
	createTestUser(t, db, secondaryOwnerID, true)

	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)
	require.NoError(t, db.Create(&relational.SystemCharacteristics{
		SystemSecurityPlanId: sspID,
		SystemNameShort:      "Digest SSP",
	}).Error)

	createDigestRisk(t, db, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Fresh risk",
		Status:             string(riskrel.RiskStatusOpen),
		Likelihood:         strPtr("moderate"),
		Impact:             strPtr("high"),
		CreatedAt:          now.Add(-20 * time.Hour),
		LastSeenAt:         now.Add(-20 * time.Hour),
		Assignments:        []uuid.UUID{recipientID, secondaryOwnerID},
	})
	createDigestRisk(t, db, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Overdue risk",
		Status:             string(riskrel.RiskStatusInvestigating),
		Likelihood:         strPtr("high"),
		Impact:             strPtr("critical"),
		CreatedAt:          now.Add(-40 * 24 * time.Hour),
		LastSeenAt:         now.Add(-2 * 24 * time.Hour),
		Assignments:        []uuid.UUID{recipientID},
	})
	createDigestRisk(t, db, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Stale risk",
		Status:             string(riskrel.RiskStatusMitigatingPlanned),
		Likelihood:         strPtr("low"),
		Impact:             strPtr("moderate"),
		CreatedAt:          now.Add(-10 * 24 * time.Hour),
		LastSeenAt:         now.Add(-40 * 24 * time.Hour),
		Assignments:        []uuid.UUID{recipientID},
	})
	reviewDeadline := now.Add(7 * 24 * time.Hour)
	createDigestRisk(t, db, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Accepted risk",
		Status:             string(riskrel.RiskStatusRiskAccepted),
		Likelihood:         strPtr("moderate"),
		Impact:             strPtr("high"),
		CreatedAt:          now.Add(-60 * 24 * time.Hour),
		LastSeenAt:         now.Add(-5 * 24 * time.Hour),
		ReviewDeadline:     &reviewDeadline,
		Assignments:        []uuid.UUID{recipientID},
	})
	overdueReviewDeadline := now.Add(-2 * 24 * time.Hour)
	createDigestRisk(t, db, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Overdue accepted risk",
		Status:             string(riskrel.RiskStatusRiskAccepted),
		Likelihood:         strPtr("high"),
		Impact:             strPtr("high"),
		CreatedAt:          now.Add(-90 * 24 * time.Hour),
		LastSeenAt:         now.Add(-6 * 24 * time.Hour),
		ReviewDeadline:     &overdueReviewDeadline,
		Assignments:        []uuid.UUID{recipientID},
	})

	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	ctx := context.Background()
	mockRepo.On("FindUserByID", ctx, recipientID.String()).Return(NotificationUser{
		ID:        recipientID.String(),
		Email:     "recipient@example.com",
		FirstName: "Recipient",
		LastName:  "Owner",
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateRiskNotifications,
				Channels:         []string{notification.DeliveryChannelEmail},
			},
		},
	}, nil)
	mockEmail.On("UseTemplate", "risk-open-digest", mock.MatchedBy(func(data map[string]interface{}) bool {
		newItems, ok := data["NewSinceLastDigest"].([]RiskDigestEmailItem)
		if !ok || len(newItems) != 1 || newItems[0].Title != "Fresh risk" {
			return false
		}
		if newItems[0].OwnerName != "Risk Owner, Risk Owner" {
			return false
		}
		overdueItems, ok := data["OverdueForAction"].([]RiskDigestEmailItem)
		if !ok || len(overdueItems) != 1 || overdueItems[0].Title != "Overdue risk" {
			return false
		}
		staleItems, ok := data["StaleRisks"].([]RiskDigestEmailItem)
		if !ok || len(staleItems) != 1 || staleItems[0].Title != "Stale risk" {
			return false
		}
		overdueReviewItems, ok := data["OverdueReview"].([]RiskDigestEmailItem)
		if !ok || len(overdueReviewItems) != 1 || overdueReviewItems[0].Title != "Overdue accepted risk" {
			return false
		}
		dueItems, ok := data["DueForReview"].([]RiskDigestEmailItem)
		if !ok || len(dueItems) != 1 || dueItems[0].Title != "Accepted risk" {
			return false
		}
		return data["RecipientName"] == "Recipient Owner"
	})).Return("<html>digest</html>", "digest", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "recipient@example.com" && strings.Contains(msg.Subject, "risk digest")
	})).Return(&types.SendResult{Success: true, MessageID: "msg-1"}, nil)

	worker := NewRiskOpenDigestWorker(db, mockRepo, "https://app.example.com", newTestRiskNotificationServiceFactory(mockEmail, nil), logger)
	worker.now = func() time.Time { return now }

	err := worker.Work(ctx, &river.Job[RiskOpenDigestArgs]{
		Args: RiskOpenDigestArgs{
			RecipientUserID: recipientID,
			WindowStart:     windowStart.Format(time.RFC3339),
			WindowEnd:       windowEnd.Format(time.RFC3339),
			WindowKind:      riskDigestWindowDaily,
		},
	})
	require.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockEmail.AssertExpectations(t)
}

func TestRiskOpenDigestWorker_UnsubscribedUser_Skips(t *testing.T) {
	mockEmail := &MockEmailService{}
	mockRepo := &MockUserRepository{}
	ctx := context.Background()
	logger := zap.NewNop().Sugar()
	recipientID := uuid.New()

	mockRepo.On("FindUserByID", ctx, recipientID.String()).Return(NotificationUser{
		ID:        recipientID.String(),
		Email:     "recipient@example.com",
		FirstName: "Recipient",
	}, nil)

	worker := NewRiskOpenDigestWorker(newRiskWorkersTestDB(t), mockRepo, "https://app.example.com", newTestRiskNotificationServiceFactory(mockEmail, nil), logger)
	err := worker.Work(ctx, &river.Job[RiskOpenDigestArgs]{
		Args: RiskOpenDigestArgs{
			RecipientUserID: recipientID,
			WindowStart:     "2026-03-22T00:00:00Z",
			WindowEnd:       "2026-03-23T00:00:00Z",
			WindowKind:      riskDigestWindowDaily,
		},
	})
	require.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}

func TestRiskOpenDigestWorker_SlackSubscribed_SendsSlack(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	now := time.Date(2026, 3, 23, 12, 0, 0, 0, time.UTC)
	windowStart := time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
	windowEnd := time.Date(2026, 3, 23, 0, 0, 0, 0, time.UTC)

	recipientID := uuid.New()
	createTestUser(t, db, recipientID, false)

	sspID := uuid.New()
	require.NoError(t, db.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)
	require.NoError(t, db.Create(&relational.SystemCharacteristics{
		SystemSecurityPlanId: sspID,
		SystemNameShort:      "Digest SSP",
	}).Error)

	createDigestRisk(t, db, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Fresh risk",
		Status:             string(riskrel.RiskStatusOpen),
		Likelihood:         strPtr("moderate"),
		Impact:             strPtr("high"),
		CreatedAt:          now.Add(-20 * time.Hour),
		LastSeenAt:         now.Add(-20 * time.Hour),
		Assignments:        []uuid.UUID{recipientID},
	})

	mockEmail := &MockEmailService{}
	mockSlack := &MockSlackService{}
	mockRepo := &MockUserRepository{}
	ctx := context.Background()
	mockRepo.On("FindUserByID", ctx, recipientID.String()).Return(NotificationUser{
		ID:          recipientID.String(),
		Email:       "recipient@example.com",
		FirstName:   "Recipient",
		LastName:    "Owner",
		SlackUserID: "URISKDIGEST",
		NotificationSubscriptions: []NotificationSubscription{
			{
				NotificationType: notification.SubscriptionGateRiskNotifications,
				Channels:         []string{notification.DeliveryChannelSlack},
			},
		},
	}, nil)
	mockSlack.On("IsEnabled").Return(true).Once()
	mockSlack.On("SendMessage", ctx, "URISKDIGEST", mock.MatchedBy(func(msg *slacktypes.Message) bool {
		return msg != nil &&
			strings.Contains(msg.Text, "Risk digest:") &&
			len(msg.Blocks) > 0
	})).Return(&slacktypes.SendResult{Success: true, DeliveryID: "slack-digest-1"}, nil).Once()

	worker := NewRiskOpenDigestWorker(db, mockRepo, "https://app.example.com", newTestRiskNotificationServiceFactory(mockEmail, mockSlack), logger)
	worker.now = func() time.Time { return now }

	err := worker.Work(ctx, &river.Job[RiskOpenDigestArgs]{
		Args: RiskOpenDigestArgs{
			RecipientUserID: recipientID,
			WindowStart:     windowStart.Format(time.RFC3339),
			WindowEnd:       windowEnd.Format(time.RFC3339),
			WindowKind:      riskDigestWindowDaily,
		},
	})
	require.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockSlack.AssertExpectations(t)
	mockEmail.AssertNotCalled(t, "UseTemplate", mock.Anything, mock.Anything)
	mockEmail.AssertNotCalled(t, "Send", mock.Anything, mock.Anything)
}

type digestRiskSeed struct {
	ID                 uuid.UUID
	SSPID              uuid.UUID
	PrimaryOwnerUserID *uuid.UUID
	Title              string
	Status             string
	Likelihood         *string
	Impact             *string
	CreatedAt          time.Time
	LastSeenAt         time.Time
	ReviewDeadline     *time.Time
	Assignments        []uuid.UUID
}

func createDigestRisk(t *testing.T, db *gorm.DB, seed digestRiskSeed) {
	t.Helper()
	require.NoError(t, db.Create(&riskrel.Risk{
		UUIDModel:          relational.UUIDModel{ID: &seed.ID},
		Title:              seed.Title,
		Description:        seed.Title,
		Status:             seed.Status,
		SSPID:              seed.SSPID,
		PrimaryOwnerUserID: seed.PrimaryOwnerUserID,
		Likelihood:         seed.Likelihood,
		Impact:             seed.Impact,
		SourceType:         string(riskrel.RiskSourceTypeManual),
		ReviewDeadline:     seed.ReviewDeadline,
		FirstSeenAt:        seed.CreatedAt,
		LastSeenAt:         seed.LastSeenAt,
		CreatedAt:          seed.CreatedAt,
		UpdatedAt:          seed.CreatedAt,
	}).Error)
	for i, ownerID := range seed.Assignments {
		require.NoError(t, db.Create(&riskrel.RiskOwnerAssignment{
			RiskID:    seed.ID,
			OwnerKind: "user",
			OwnerRef:  ownerID.String(),
			IsPrimary: i == 0,
		}).Error)
	}
}

func strPtr(v string) *string {
	return &v
}
