package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNotificationKindForReasonMapsRevocationVsDrift(t *testing.T) {
	require.Equal(t, leverageRevokedNotificationKind, notificationKindForReason("upstream offering revoked"))
	require.Equal(t, leverageRevokedNotificationKind, notificationKindForReason("leveraged authorization revoked"))
	require.Equal(t, leverageDriftedNotificationKind, notificationKindForReason("upstream offering content changed"))
	require.Equal(t, leverageDriftedNotificationKind, notificationKindForReason("upstream offering deprecated"))
}

func TestLeverageDriftNotificationWorker_DispatchesEmailOnRevocation(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	risk, ownerID := createTestRiskWithOwner(t, db, riskrel.RiskStatusOpen, nil, time.Now().UTC())
	require.NoError(t, db.Model(&riskrel.Risk{}).Where("id = ?", risk.ID).Update("source_type", string(riskrel.RiskSourceTypeInheritedRevoked)).Error)
	createTestUser(t, db, ownerID, true)

	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "leverage-revoked", mock.Anything).Return("<html>ok</html>", "ok", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", mock.Anything, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == ownerID.String()+"@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "leverage-msg"}, nil)

	userRepo := NewGORMUserRepository(db)
	worker := NewLeverageDriftNotificationWorker(db, userRepo, "https://app.example.com", newTestRiskNotificationServiceFactory(mockEmail, nil), logger)

	err := worker.Work(context.Background(), &river.Job[LeverageDriftNotificationArgs]{
		Args: LeverageDriftNotificationArgs{
			RiskID:      *risk.ID,
			LinkID:      uuid.New(),
			OwnerUserID: ownerID,
			Channel:     notification.DeliveryChannelEmail,
			Reason:      "upstream offering revoked",
		},
	})
	require.NoError(t, err)
	mockEmail.AssertExpectations(t)
}

func TestLeverageDriftNotificationWorker_RespectsSubscription(t *testing.T) {
	db := newRiskWorkersTestDB(t)
	logger := zap.NewNop().Sugar()
	risk, ownerID := createTestRiskWithOwner(t, db, riskrel.RiskStatusOpen, nil, time.Now().UTC())
	createTestUser(t, db, ownerID, false)

	mockEmail := &MockEmailService{}
	userRepo := NewGORMUserRepository(db)
	worker := NewLeverageDriftNotificationWorker(db, userRepo, "https://app.example.com", newTestRiskNotificationServiceFactory(mockEmail, nil), logger)

	err := worker.Work(context.Background(), &river.Job[LeverageDriftNotificationArgs]{
		Args: LeverageDriftNotificationArgs{
			RiskID:      *risk.ID,
			LinkID:      uuid.New(),
			OwnerUserID: ownerID,
			Channel:     notification.DeliveryChannelEmail,
			Reason:      "upstream offering content changed",
		},
	})
	require.NoError(t, err)
	mockEmail.AssertNotCalled(t, "Send")
}
