package digest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
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

type digestStubTransport struct {
	deliveries []notification.Delivery
}

func (t *digestStubTransport) Enqueue(_ context.Context, deliveries []notification.Delivery) error {
	t.deliveries = append(t.deliveries, deliveries...)
	return nil
}

func (t *digestStubTransport) byProvider(provider string) []notification.Delivery {
	out := make([]notification.Delivery, 0)
	for i := range t.deliveries {
		if t.deliveries[i].Provider == provider {
			out = append(out, t.deliveries[i])
		}
	}
	return out
}

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

func TestHasGlobalDigestDestinations_RequiresConfiguredDestination(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	service := NewService(
		db,
		nil,
		&config.Config{Slack: &config.SlackConfig{Enabled: true}},
		zap.NewNop().Sugar(),
	)

	assert.False(t, service.hasGlobalDigestDestinations(context.Background()))

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelEmail,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				emailprovider.AddressKeyEmail: "alerts@example.com",
			},
		}),
	}).Error)

	assert.True(t, service.hasGlobalDigestDestinations(context.Background()))
}

func TestDispatchEvidenceDigestNotificationsSupportsMultipleConfiguredDestinations(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.SystemNotificationDestination{}))

	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelSlack,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				slackprovider.AddressKeyChannel:    "ccf-alerts",
				slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
			},
		}),
	}).Error)
	require.NoError(t, db.Create(&relational.SystemNotificationDestination{
		NotificationType: notification.SubscriptionGateEvidenceDigest,
		Provider:         notification.DeliveryChannelEmail,
		Target: datatypes.NewJSONType(relational.SystemNotificationTarget{
			Address: map[string]string{
				emailprovider.AddressKeyEmail: "alerts@example.com",
			},
		}),
	}).Error)

	registry := notification.MustNewRegistry(notification.NewDefinition(
		evidenceDigestKind,
		notification.SubscriptionGateEvidenceDigest,
		notification.BindRenderer(notification.DeliveryChannelEmail, notification.ProviderRenderer(notification.DeliveryChannelEmail, func(context.Context, any) (any, error) {
			return emailprovider.Content{From: "from@example.com", Subject: "Digest", TextBody: "body"}, nil
		})),
		notification.BindRenderer(notification.DeliveryChannelSlack, notification.ProviderRenderer(notification.DeliveryChannelSlack, func(context.Context, any) (any, error) {
			return slackprovider.Content{Text: "body"}, nil
		})),
	))
	transport := &digestStubTransport{}
	notifier := notification.NewService(transport, registry, notification.NewResolver(nil, nil, nil))

	service := NewService(db, notifier, &config.Config{}, zap.NewNop().Sugar())
	err = service.dispatchEvidenceDigestNotifications(context.Background(), &EvidenceSummary{TotalCount: 1}, "", time.Now().UTC(), true, false)
	require.NoError(t, err)

	emails := transport.byProvider(notification.DeliveryChannelEmail)
	slacks := transport.byProvider(notification.DeliveryChannelSlack)

	require.Len(t, emails, 1)
	assert.Equal(t, "alerts@example.com", emails[0].Target.Address[emailprovider.AddressKeyEmail])

	require.Len(t, slacks, 1)
	assert.Equal(t, "ccf-alerts", slacks[0].Target.Address[slackprovider.AddressKeyChannel])
}
