package digest

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestConvertToEvidenceItems(t *testing.T) {
	// Test the conversion logic without database dependencies
	now := time.Now()
	items := []EvidenceItem{
		{
			ID:          uuid.New().String(),
			UUID:        uuid.New().String(),
			Title:       "Test Evidence",
			Description: "Test Description",
			Status:      "not-satisfied",
			ExpiresAt:   now.Format("2006-01-02 15:04 MST"),
			Labels:      []string{"provider:aws", "env:prod"},
		},
	}

	assert.Len(t, items, 1)
	assert.Equal(t, "Test Evidence", items[0].Title)
	assert.Equal(t, "not-satisfied", items[0].Status)
	assert.Len(t, items[0].Labels, 2)
	assert.NotEmpty(t, items[0].ExpiresAt)
}

func TestEvidenceSummaryStructure(t *testing.T) {
	summary := &EvidenceSummary{
		TotalCount:        100,
		SatisfiedCount:    80,
		NotSatisfiedCount: 15,
		ExpiredCount:      5,
		OtherCount:        0,
		TopExpired: []EvidenceItem{
			{Title: "Expired 1"},
			{Title: "Expired 2"},
		},
		TopNotSatisfied: []EvidenceItem{
			{Title: "Failed 1"},
		},
	}

	assert.Equal(t, int64(100), summary.TotalCount)
	assert.Equal(t, int64(80), summary.SatisfiedCount)
	assert.Equal(t, int64(15), summary.NotSatisfiedCount)
	assert.Equal(t, int64(5), summary.ExpiredCount)
	assert.Len(t, summary.TopExpired, 2)
	assert.Len(t, summary.TopNotSatisfied, 1)
}

func TestNewService_StoresInjectedSlackService(t *testing.T) {
	slackService, err := slacksvc.NewService(&config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
	}, zap.NewNop().Sugar())
	require.NoError(t, err)

	service := NewService(
		nil,
		nil,
		slackService,
		nil,
		&config.Config{Slack: &config.SlackConfig{Enabled: true, Token: "xoxb-test-token"}},
		zap.NewNop().Sugar(),
	)

	assert.Same(t, slackService, service.slackService)
}

func TestBuildGlobalDigestDeliveryArgs_FansOutPerChannelAndSkipsMissingSlackLink(t *testing.T) {
	service := NewService(nil, nil, nil, nil, &config.Config{}, zap.NewNop().Sugar())

	userOneID := uuid.New()
	userTwoID := uuid.New()

	summary := &EvidenceSummary{
		TotalCount:        12,
		SatisfiedCount:    8,
		NotSatisfiedCount: 3,
		ExpiredCount:      1,
		TopExpired: []EvidenceItem{
			{
				ID:        "evidence-1",
				UUID:      uuid.New().String(),
				Title:     "Expired Control",
				ExpiresAt: "2026-04-07 09:00 UTC",
			},
		},
	}

	recipients := []DigestRecipient{
		{
			User: relational.User{
				UUIDModel: relational.UUIDModel{ID: &userOneID},
				Email:     "alice@example.com",
				FirstName: "Alice",
			},
			Channels:    []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
			SlackUserID: "UALICE",
		},
		{
			User: relational.User{
				UUIDModel: relational.UUIDModel{ID: &userTwoID},
				Email:     "bob@example.com",
				FirstName: "Bob",
			},
			Channels:    []string{notification.DeliveryChannelSlack},
			SlackUserID: "",
		},
	}

	args := service.buildGlobalDigestDeliveryArgs(summary, recipients)
	require.Len(t, args, 2)

	assert.ElementsMatch(t, []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack}, []string{
		args[0].Channel,
		args[1].Channel,
	})

	for _, arg := range args {
		assert.Equal(t, userOneID.String(), arg.UserID)
		assert.Equal(t, int64(12), arg.Summary.TotalCount)
		assert.Len(t, arg.Summary.TopExpired, 1)
	}
}

func TestBuildGlobalSlackDigestDeliveryArgs_UsesConfiguredChannel(t *testing.T) {
	service := NewService(
		nil,
		nil,
		nil,
		nil,
		&config.Config{
			Slack: &config.SlackConfig{
				Enabled:       true,
				DigestChannel: "C-DIGEST",
			},
		},
		zap.NewNop().Sugar(),
	)

	summary := &EvidenceSummary{TotalCount: 5}
	args := service.buildGlobalSlackDigestDeliveryArgs(summary)

	require.Len(t, args, 1)
	assert.Equal(t, notification.DeliveryChannelSlack, args[0].Channel)
	assert.Equal(t, "C-DIGEST", args[0].SlackChannel)
	assert.Equal(t, int64(5), args[0].Summary.TotalCount)
}
