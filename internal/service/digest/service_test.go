package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

func TestNewService_StoresInjectedNotifier(t *testing.T) {
	notifier := notification.NewService(nil, nil, nil)

	service := NewService(
		nil,
		notifier,
		&config.Config{Slack: &config.SlackConfig{Enabled: true, Token: "xoxb-test-token"}},
		zap.NewNop().Sugar(),
	)

	assert.Same(t, notifier, service.notifier)
}

func TestEvidenceDigestDispatchOptions_UsesCorrelationAndSourceJobKind(t *testing.T) {
	generatedAt := time.Date(2026, 4, 14, 17, 32, 10, 123, time.UTC)

	options := evidenceDigestDispatchOptions(generatedAt)

	assert.Equal(t, "send_global_digest", options.SourceJobKind)
	assert.True(t, strings.HasPrefix(options.CorrelationID, "evidence-digest:"))
}

func TestGlobalDigestSlackEnabled_RequiresConfiguredChannel(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	service := NewService(
		db,
		nil,
		&config.Config{Slack: &config.SlackConfig{Enabled: true}},
		zap.NewNop().Sugar(),
	)

	assert.False(t, service.globalDigestSlackEnabled(context.Background()))

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.NotificationTypeEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				slackprovider.AddressKeyChannel:    "ccf-alerts",
				slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
			},
		}),
	}).Error)

	assert.True(t, service.globalDigestSlackEnabled(context.Background()))
}
