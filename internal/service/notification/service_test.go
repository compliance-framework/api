package notification

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubTransport struct {
	deliveries []Delivery
}

func (t *stubTransport) Enqueue(_ context.Context, deliveries []Delivery) error {
	t.deliveries = append(t.deliveries, deliveries...)
	return nil
}

func (t *stubTransport) byChannel(channel string) []Delivery {
	out := make([]Delivery, 0)
	for i := range t.deliveries {
		if t.deliveries[i].Provider == channel {
			out = append(out, t.deliveries[i])
		}
	}
	return out
}

func TestServiceDispatchEnqueuesProviderReadyDeliveries(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionGate:  SubscriptionGateRiskNotifications,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "Risk review due", TextBody: "Email body"}, nil
			}),
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
				return map[string]string{"text": "Slack body"}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:    "user-1",
				Email: "user@example.com",
				Identities: map[string]map[string]string{
					DeliveryChannelEmail: {"email": "user@example.com"},
					DeliveryChannelSlack: {"channel": "U123", "target_type": "direct_message"},
				},
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateRiskNotifications,
						Channels:         []string{DeliveryChannelEmail, DeliveryChannelSlack},
					},
				},
			},
		},
	}, nil, nil)

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver)

	err := service.Dispatch(context.Background(), Request{
		Kind: Kind("risk_review_due"),
		Audiences: []Audience{
			{User: &UserAudience{UserID: "user-1"}},
		},
		Model: map[string]any{"RiskTitle": "Open port"},
		Options: DispatchOptions{
			CorrelationID: "corr-1",
			SourceJobKind: "risk_digest",
			SourceJobID:   "job-42",
		},
	})
	require.NoError(t, err)

	emails := transport.byChannel(DeliveryChannelEmail)
	slacks := transport.byChannel(DeliveryChannelSlack)

	require.Len(t, emails, 1)
	assert.Equal(t, "user@example.com", emails[0].Target.Address["email"])
	emailContent, ok := emails[0].Content.Payload.(testEmailContent)
	require.True(t, ok)
	assert.Equal(t, "from@example.com", emailContent.From)
	assert.Equal(t, Kind("risk_review_due"), emails[0].Metadata.NotificationKind)
	assert.Equal(t, DeliveryChannelEmail, emails[0].Metadata.Provider)
	assert.Equal(t, "user-1", emails[0].Metadata.RecipientUserID)
	assert.Equal(t, "corr-1", emails[0].Metadata.CorrelationID)
	assert.Equal(t, "risk_digest", emails[0].Metadata.SourceJobKind)
	assert.Equal(t, "job-42", emails[0].Metadata.SourceJobID)

	require.Len(t, slacks, 1)
	assert.Equal(t, "U123", slacks[0].Target.Address["channel"])
	targetType, ok := slacks[0].Target.Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, "direct_message", targetType)
	assert.Equal(t, Kind("risk_review_due"), slacks[0].Metadata.NotificationKind)
	assert.Equal(t, DeliveryChannelSlack, slacks[0].Metadata.Provider)
	assert.Equal(t, "user-1", slacks[0].Metadata.RecipientUserID)
}

func TestServiceDispatchNoTargetsBecomesNoop(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionGate:  SubscriptionGateRiskNotifications,
		SupportedChannels: []string{DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
				return map[string]string{"text": "Slack body"}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:    "user-1",
				Email: "user@example.com",
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateRiskNotifications,
						Channels:         []string{DeliveryChannelSlack},
					},
				},
			},
		},
	}, nil, nil)

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver)

	err := service.Dispatch(context.Background(), Request{
		Kind: Kind("risk_review_due"),
		Audiences: []Audience{
			{User: &UserAudience{UserID: "user-1"}},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, transport.deliveries)
}

func TestServiceDispatchReturnsDefinitionErrorForUnknownKind(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	service := NewService(&stubTransport{}, registry, NewResolver(stubUserRepository{}, nil, nil))
	err = service.Dispatch(context.Background(), Request{
		Kind: Kind("missing"),
		Audiences: []Audience{
			{Direct: &DirectAudience{Provider: DeliveryChannelEmail, Address: map[string]string{"email": "user@example.com"}}},
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDefinitionNotFound)
}

func TestServiceDispatchFanoutSubscribedUsersBuildsPerUserDeliveries(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("evidence_digest"),
		SubscriptionGate:  SubscriptionGateEvidenceDigest,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(_ context.Context, model any) (any, error) {
				data := model.(string)
				return testEmailContent{From: "from@example.com", Subject: "Digest", TextBody: data}, nil
			}),
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(_ context.Context, model any) (any, error) {
				data := model.(string)
				return map[string]string{"text": data}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:        "user-1",
				Email:     "alice@example.com",
				FirstName: "Alice",
				Identities: map[string]map[string]string{
					DeliveryChannelEmail: {"email": "alice@example.com"},
					DeliveryChannelSlack: {"channel": "UALICE", "target_type": "direct_message"},
				},
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail, DeliveryChannelSlack},
					},
				},
			},
			"user-2": {
				ID:        "user-2",
				Email:     "bob@example.com",
				FirstName: "Bob",
				Identities: map[string]map[string]string{
					DeliveryChannelEmail: {"email": "bob@example.com"},
				},
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, nil, nil)

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver)

	err := service.DispatchFanout(context.Background(), FanoutRequest{
		SubscribedUsers: []SubscribedUsersRequest{
			{
				Kind: Kind("evidence_digest"),
				BuildModel: func(_ context.Context, user User) (any, error) {
					return "hello " + user.FirstName, nil
				},
			},
		},
	})
	require.NoError(t, err)

	emails := transport.byChannel(DeliveryChannelEmail)
	slacks := transport.byChannel(DeliveryChannelSlack)

	require.Len(t, emails, 2)
	assert.Equal(t, "alice@example.com", emails[0].Target.Address["email"])
	email0, ok := emails[0].Content.Payload.(testEmailContent)
	require.True(t, ok)
	assert.Equal(t, "hello Alice", email0.TextBody)
	assert.Equal(t, "bob@example.com", emails[1].Target.Address["email"])
	email1, ok := emails[1].Content.Payload.(testEmailContent)
	require.True(t, ok)
	assert.Equal(t, "hello Bob", email1.TextBody)
	assert.Equal(t, "from@example.com", email0.From)

	require.Len(t, slacks, 1)
	assert.Equal(t, "UALICE", slacks[0].Target.Address["channel"])
	targetType, ok := slacks[0].Target.Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, "direct_message", targetType)
	slackContent, ok := slacks[0].Content.Payload.(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "hello Alice", slackContent["text"])
}

func TestServiceDispatchFanoutSupportsSharedAndSubscribedRequests(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("evidence_digest"),
		SubscriptionGate:  SubscriptionGateEvidenceDigest,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(_ context.Context, model any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "Digest", TextBody: model.(string)}, nil
			}),
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(_ context.Context, model any) (any, error) {
				return map[string]string{"text": model.(string)}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:        "user-1",
				Email:     "alice@example.com",
				FirstName: "Alice",
				Identities: map[string]map[string]string{
					DeliveryChannelEmail: {"email": "alice@example.com"},
				},
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, stubConfiguredDestinationResolver{
		destinations: map[string]ConfiguredDestination{
			"slack.digest_channel": {
				Provider: DeliveryChannelSlack,
				Address: map[string]string{
					"channel":     "C-DIGEST",
					"target_type": "channel",
				},
			},
		},
	}, nil)

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver)

	err := service.DispatchFanout(context.Background(), FanoutRequest{
		Requests: []Request{
			{
				Kind: Kind("evidence_digest"),
				Audiences: []Audience{
					{ConfiguredDestination: &ConfiguredDestinationAudience{Key: "slack.digest_channel"}},
				},
				Model: "shared digest",
			},
		},
		SubscribedUsers: []SubscribedUsersRequest{
			{
				Kind:  Kind("evidence_digest"),
				Model: "personal digest",
			},
		},
	})
	require.NoError(t, err)

	emails := transport.byChannel(DeliveryChannelEmail)
	slacks := transport.byChannel(DeliveryChannelSlack)

	require.Len(t, emails, 1)
	assert.Equal(t, "alice@example.com", emails[0].Target.Address["email"])
	emailContent, ok := emails[0].Content.Payload.(testEmailContent)
	require.True(t, ok)
	assert.Equal(t, "personal digest", emailContent.TextBody)

	require.Len(t, slacks, 1)
	assert.Equal(t, "C-DIGEST", slacks[0].Target.Address["channel"])
	targetType, ok := slacks[0].Target.Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, "channel", targetType)
	slackContent, ok := slacks[0].Content.Payload.(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "shared digest", slackContent["text"])
}

func TestServiceDispatchFanoutDeliversEachRequestWithoutIdempotencyDedup(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("evidence_digest"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(_ context.Context, model any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "Digest", TextBody: model.(string)}, nil
			}),
		},
	})

	service := NewService(&stubTransport{}, registry, NewResolver(nil, nil, nil))
	transport := service.transport.(*stubTransport)

	request := Request{
		Kind: Kind("evidence_digest"),
		Audiences: []Audience{
			{Direct: &DirectAudience{Provider: DeliveryChannelEmail, Address: map[string]string{"email": "alice@example.com"}}},
		},
		Model: "same payload",
	}

	err := service.DispatchFanout(context.Background(), FanoutRequest{
		Requests: []Request{request, request},
	})
	require.NoError(t, err)
	emails := transport.byChannel(DeliveryChannelEmail)
	require.Len(t, emails, 2)
	assert.Equal(t, "alice@example.com", emails[0].Target.Address["email"])
}
