//go:build integration

package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational"
	riskrel "github.com/compliance-framework/api/internal/service/relational/risks"
	"github.com/compliance-framework/api/internal/tests"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type RiskOpenDigestIntegrationSuite struct {
	tests.IntegrationTestSuite
	logger *zap.SugaredLogger
}

func TestRiskOpenDigestIntegration(t *testing.T) {
	suite.Run(t, new(RiskOpenDigestIntegrationSuite))
}

func (suite *RiskOpenDigestIntegrationSuite) SetupSuite() {
	suite.IntegrationTestSuite.SetupSuite()
	logger, _ := zap.NewDevelopment()
	suite.logger = logger.Sugar()
	suite.Config.WebBaseURL = "https://app.example.com"
}

func (suite *RiskOpenDigestIntegrationSuite) SetupTest() {
	err := suite.Migrator.Refresh()
	suite.Require().NoError(err)
}

func (suite *RiskOpenDigestIntegrationSuite) TestRiskOpenDigestSchedulerAndWorker() {
	ctx := context.Background()
	now := time.Date(2026, 3, 23, 12, 0, 0, 0, time.UTC)

	recipientID := uuid.New()
	suite.Require().NoError(suite.DB.Model(&relational.User{}).Create(map[string]interface{}{
		"id":                            recipientID,
		"email":                         "recipient@example.com",
		"first_name":                    "Recipient",
		"last_name":                     "Owner",
		"auth_method":                   "password",
		"risk_notifications_subscribed": true,
	}).Error)

	sspID := uuid.New()
	suite.Require().NoError(suite.DB.Create(&relational.SystemSecurityPlan{
		UUIDModel: relational.UUIDModel{ID: &sspID},
	}).Error)
	suite.Require().NoError(suite.DB.Create(&relational.SystemCharacteristics{
		SystemSecurityPlanId: sspID,
		SystemNameShort:      "Digest SSP",
	}).Error)

	createDigestRisk(suite.T(), suite.DB, digestRiskSeed{
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
	createDigestRisk(suite.T(), suite.DB, digestRiskSeed{
		ID:                 uuid.New(),
		SSPID:              sspID,
		PrimaryOwnerUserID: &recipientID,
		Title:              "Overdue risk",
		Status:             string(riskrel.RiskStatusInvestigating),
		Likelihood:         strPtr("high"),
		Impact:             strPtr("critical"),
		CreatedAt:          now.Add(-45 * 24 * time.Hour),
		LastSeenAt:         now.Add(-2 * 24 * time.Hour),
		Assignments:        []uuid.UUID{recipientID},
	})
	reviewDeadline := now.Add(7 * 24 * time.Hour)
	createDigestRisk(suite.T(), suite.DB, digestRiskSeed{
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
	overdueReviewDeadline := now.Add(-3 * 24 * time.Hour)
	createDigestRisk(suite.T(), suite.DB, digestRiskSeed{
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

	client := &stubRiverClient{}
	scheduler := NewRiskOpenDigestSchedulerWorker(suite.DB, client, riskDigestWindowDaily, suite.logger)
	scheduler.now = func() time.Time { return now }

	err := scheduler.Work(ctx, &river.Job[RiskOpenDigestSchedulerArgs]{})
	suite.Require().NoError(err)
	suite.Require().Len(client.params, 1)

	jobArgs, ok := client.params[0].Args.(RiskOpenDigestArgs)
	suite.Require().True(ok)
	suite.Equal(recipientID, jobArgs.RecipientUserID)

	mockEmail := &MockEmailService{}
	mockEmail.On("UseTemplate", "risk-open-digest", mock.MatchedBy(func(data map[string]interface{}) bool {
		newItems, ok := data["NewSinceLastDigest"].([]RiskDigestEmailItem)
		if !ok || len(newItems) != 1 || newItems[0].Title != "Fresh risk" {
			return false
		}
		overdueItems, ok := data["OverdueForAction"].([]RiskDigestEmailItem)
		if !ok || len(overdueItems) != 1 || overdueItems[0].Title != "Overdue risk" {
			return false
		}
		overdueReviewItems, ok := data["OverdueReview"].([]RiskDigestEmailItem)
		if !ok || len(overdueReviewItems) != 1 || overdueReviewItems[0].Title != "Overdue accepted risk" {
			return false
		}
		dueItems, ok := data["DueForReview"].([]RiskDigestEmailItem)
		return ok && len(dueItems) == 1 && dueItems[0].Title == "Accepted risk"
	})).Return("<html>digest</html>", "digest", nil)
	mockEmail.On("GetDefaultFromAddress").Return("noreply@example.com")
	mockEmail.On("Send", ctx, mock.MatchedBy(func(msg *types.Message) bool {
		return len(msg.To) == 1 && msg.To[0] == "recipient@example.com"
	})).Return(&types.SendResult{Success: true, MessageID: "msg-1"}, nil)

	worker := NewRiskOpenDigestWorker(suite.DB, mockEmail, NewGORMUserRepository(suite.DB), suite.Config.WebBaseURL, suite.logger)
	worker.now = func() time.Time { return now }

	err = worker.Work(ctx, &river.Job[RiskOpenDigestArgs]{Args: jobArgs})
	suite.Require().NoError(err)
	mockEmail.AssertExpectations(suite.T())
}
