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
		if t.deliveries[i].Channel == channel {
			out = append(out, t.deliveries[i])
		}
	}
	return out
}

func TestServiceDispatchEnqueuesProviderReadyDeliveries(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionType:  NotificationTypeRiskNotifications,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(context.Context, any) (EmailContent, error) {
				return EmailContent{Subject: "Risk review due", TextBody: "Email body"}, nil
			}),
			DeliveryChannelSlack: SlackChannelRenderer(func(context.Context, any) (SlackContent, error) {
				return SlackContent{Text: "Slack body"}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:          "user-1",
				Email:       "user@example.com",
				SlackUserID: "U123",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeRiskNotifications,
						Channels:         []string{DeliveryChannelEmail, DeliveryChannelSlack},
					},
				},
			},
		},
	}, nil)

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver, WithDefaultEmailFrom("from@example.com"))

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
	assert.Equal(t, "user@example.com", emails[0].Target.Address)
	require.NotNil(t, emails[0].Content.Email)
	assert.Equal(t, "from@example.com", emails[0].Content.Email.From)
	assert.Equal(t, Kind("risk_review_due"), emails[0].Metadata.NotificationKind)
	assert.Equal(t, DeliveryChannelEmail, emails[0].Metadata.Channel)
	assert.Equal(t, "user-1", emails[0].Metadata.RecipientUserID)
	assert.Equal(t, "corr-1", emails[0].Metadata.CorrelationID)
	assert.Equal(t, "risk_digest", emails[0].Metadata.SourceJobKind)
	assert.Equal(t, "job-42", emails[0].Metadata.SourceJobID)

	require.Len(t, slacks, 1)
	assert.Equal(t, "U123", slacks[0].Target.Address)
	targetType, ok := slacks[0].Target.Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, SlackTargetDirectMessage, targetType)
	assert.Equal(t, Kind("risk_review_due"), slacks[0].Metadata.NotificationKind)
	assert.Equal(t, DeliveryChannelSlack, slacks[0].Metadata.Channel)
	assert.Equal(t, "user-1", slacks[0].Metadata.RecipientUserID)
}

func TestServiceDispatchNoTargetsBecomesNoop(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionType:  NotificationTypeRiskNotifications,
		SupportedChannels: []string{DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelSlack: SlackChannelRenderer(func(context.Context, any) (SlackContent, error) {
				return SlackContent{Text: "Slack body"}, nil
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
						NotificationType: NotificationTypeRiskNotifications,
						Channels:         []string{DeliveryChannelSlack},
					},
				},
			},
		},
	}, nil)

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

	service := NewService(&stubTransport{}, registry, NewResolver(stubUserRepository{}, nil))
	err = service.Dispatch(context.Background(), Request{
		Kind: Kind("missing"),
		Audiences: []Audience{
			{DirectEmail: &DirectEmailAudience{Email: "user@example.com"}},
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDefinitionNotFound)
}

func TestServiceDispatchFanoutSubscribedUsersBuildsPerUserDeliveries(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("evidence_digest"),
		SubscriptionType:  NotificationTypeEvidenceDigest,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(_ context.Context, model any) (EmailContent, error) {
				data := model.(string)
				return EmailContent{Subject: "Digest", TextBody: data}, nil
			}),
			DeliveryChannelSlack: SlackChannelRenderer(func(_ context.Context, model any) (SlackContent, error) {
				data := model.(string)
				return SlackContent{Text: data}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:          "user-1",
				Email:       "alice@example.com",
				FirstName:   "Alice",
				SlackUserID: "UALICE",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail, DeliveryChannelSlack},
					},
				},
			},
			"user-2": {
				ID:        "user-2",
				Email:     "bob@example.com",
				FirstName: "Bob",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, nil)

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver, WithDefaultEmailFrom("from@example.com"))

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
	assert.Equal(t, "alice@example.com", emails[0].Target.Address)
	require.NotNil(t, emails[0].Content.Email)
	assert.Equal(t, "hello Alice", emails[0].Content.Email.TextBody)
	assert.Equal(t, "bob@example.com", emails[1].Target.Address)
	require.NotNil(t, emails[1].Content.Email)
	assert.Equal(t, "hello Bob", emails[1].Content.Email.TextBody)
	assert.Equal(t, "from@example.com", emails[0].Content.Email.From)

	require.Len(t, slacks, 1)
	assert.Equal(t, "UALICE", slacks[0].Target.Address)
	targetType, ok := slacks[0].Target.Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, SlackTargetDirectMessage, targetType)
	require.NotNil(t, slacks[0].Content.Slack)
	assert.Equal(t, "hello Alice", slacks[0].Content.Slack.Text)
}

func TestServiceDispatchFanoutSupportsSharedAndSubscribedRequests(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("evidence_digest"),
		SubscriptionType:  NotificationTypeEvidenceDigest,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(_ context.Context, model any) (EmailContent, error) {
				return EmailContent{Subject: "Digest", TextBody: model.(string)}, nil
			}),
			DeliveryChannelSlack: SlackChannelRenderer(func(_ context.Context, model any) (SlackContent, error) {
				return SlackContent{Text: model.(string)}, nil
			}),
		},
	})

	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:        "user-1",
				Email:     "alice@example.com",
				FirstName: "Alice",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, stubConfiguredDestinationResolver{
		destinations: map[string]ConfiguredDestination{
			ConfiguredDestinationSlackDigestChannel: {
				Channel: DeliveryChannelSlack,
				Address: "C-DIGEST",
				Attributes: map[string]string{
					"target_type": SlackTargetChannel,
				},
			},
		},
	})

	transport := &stubTransport{}
	service := NewService(transport, registry, resolver, WithDefaultEmailFrom("from@example.com"))

	err := service.DispatchFanout(context.Background(), FanoutRequest{
		Requests: []Request{
			{
				Kind: Kind("evidence_digest"),
				Audiences: []Audience{
					{ConfiguredDestination: &ConfiguredDestinationAudience{Key: ConfiguredDestinationSlackDigestChannel}},
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
	assert.Equal(t, "alice@example.com", emails[0].Target.Address)
	require.NotNil(t, emails[0].Content.Email)
	assert.Equal(t, "personal digest", emails[0].Content.Email.TextBody)

	require.Len(t, slacks, 1)
	assert.Equal(t, "C-DIGEST", slacks[0].Target.Address)
	targetType, ok := slacks[0].Target.Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, SlackTargetChannel, targetType)
	require.NotNil(t, slacks[0].Content.Slack)
	assert.Equal(t, "shared digest", slacks[0].Content.Slack.Text)
}

func TestServiceDispatchFanoutDeliversEachRequestWithoutIdempotencyDedup(t *testing.T) {
	registry := MustNewRegistry(Definition{
		Kind:              Kind("evidence_digest"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(_ context.Context, model any) (EmailContent, error) {
				return EmailContent{Subject: "Digest", TextBody: model.(string)}, nil
			}),
		},
	})

	service := NewService(&stubTransport{}, registry, NewResolver(nil, nil), WithDefaultEmailFrom("from@example.com"))
	transport := service.transport.(*stubTransport)

	request := Request{
		Kind: Kind("evidence_digest"),
		Audiences: []Audience{
			{DirectEmail: &DirectEmailAudience{Email: "alice@example.com"}},
		},
		Model: "same payload",
	}

	err := service.DispatchFanout(context.Background(), FanoutRequest{
		Requests: []Request{request, request},
	})
	require.NoError(t, err)
	emails := transport.byChannel(DeliveryChannelEmail)
	require.Len(t, emails, 2)
	assert.Equal(t, "alice@example.com", emails[0].Target.Address)
}
