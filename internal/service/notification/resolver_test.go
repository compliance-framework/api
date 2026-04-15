package notification

import (
	"context"
	"sort"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubUserRepository struct {
	users map[string]User
	err   error
}

func (r stubUserRepository) FindUserByID(_ context.Context, userID string) (User, error) {
	if r.err != nil {
		return User{}, r.err
	}
	return r.users[userID], nil
}

func (r stubUserRepository) ListActiveUsersByNotificationType(_ context.Context, notificationType string) ([]User, error) {
	if r.err != nil {
		return nil, r.err
	}

	canonicalType, ok := NormalizeNotificationType(notificationType)
	if !ok {
		return []User{}, nil
	}

	users := make([]User, 0, len(r.users))
	for _, user := range r.users {
		if len(user.NotificationChannels(canonicalType)) == 0 {
			continue
		}
		users = append(users, user)
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Email < users[j].Email
	})

	return users, nil
}

type stubConfiguredDestinationResolver struct {
	destinations map[string]ConfiguredDestination
	err          error
}

func (r stubConfiguredDestinationResolver) ResolveConfiguredDestination(_ context.Context, key string) (ConfiguredDestination, error) {
	if r.err != nil {
		return ConfiguredDestination{}, r.err
	}
	return r.destinations[key], nil
}

func TestResolverResolveUserAudienceUsesSubscriptionsAndSkipsMissingSlackLink(t *testing.T) {
	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:    "user-1",
				Email: "user@example.com",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeRiskNotifications,
						Channels:         []string{DeliveryChannelEmail, DeliveryChannelSlack},
					},
				},
			},
		},
	}, nil)

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("risk_review_due"),
		Audiences: []Audience{
			{User: &UserAudience{UserID: "user-1"}},
		},
	}, Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionType:  NotificationTypeRiskNotifications,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(context.Context, any) (EmailContent, error) {
				return EmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
			DeliveryChannelSlack: SlackChannelRenderer(func(context.Context, any) (SlackContent, error) {
				return SlackContent{Text: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, DeliveryChannelEmail, targets[0].Channel)
	assert.Equal(t, "user@example.com", targets[0].Address)
}

func TestResolverResolveDirectEmailAudienceBypassesSubscriptionsByDesign(t *testing.T) {
	resolver := NewResolver(nil, nil)

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("forgot_password"),
		Audiences: []Audience{
			{DirectEmail: &DirectEmailAudience{Email: "reset@example.com"}},
		},
	}, Definition{
		Kind:              Kind("forgot_password"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(context.Context, any) (EmailContent, error) {
				return EmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, DeliveryChannelEmail, targets[0].Channel)
	assert.Equal(t, "reset@example.com", targets[0].Address)
}

func TestResolverResolveDirectSlackAudienceUsesExplicitTargetType(t *testing.T) {
	resolver := NewResolver(nil, nil)

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("system_alert"),
		Audiences: []Audience{
			{DirectSlack: &DirectSlackAudience{
				Channel:    "U123",
				TargetType: SlackTargetDirectMessage,
			}},
		},
	}, Definition{
		Kind:              Kind("system_alert"),
		SupportedChannels: []string{DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelSlack: SlackChannelRenderer(func(context.Context, any) (SlackContent, error) {
				return SlackContent{Text: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "U123", targets[0].Address)
	targetType, ok := targets[0].Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, SlackTargetDirectMessage, targetType)
}

func TestResolverResolveConfiguredDestinationAudience(t *testing.T) {
	resolver := NewResolver(nil, stubConfiguredDestinationResolver{
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

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("evidence_digest"),
		Audiences: []Audience{
			{ConfiguredDestination: &ConfiguredDestinationAudience{Key: ConfiguredDestinationSlackDigestChannel}},
		},
	}, Definition{
		Kind:              Kind("evidence_digest"),
		SupportedChannels: []string{DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelSlack: SlackChannelRenderer(func(context.Context, any) (SlackContent, error) {
				return SlackContent{Text: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "C-DIGEST", targets[0].Address)
	targetType, ok := targets[0].Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, SlackTargetChannel, targetType)
}

func TestConfigDestinationResolverResolveSlackDigestChannel(t *testing.T) {
	resolver := NewConfigDestinationResolver(&config.Config{
		Slack: &config.SlackConfig{
			Enabled:       true,
			DigestChannel: "C-DIGEST",
		},
	})

	destination, err := resolver.ResolveConfiguredDestination(context.Background(), ConfiguredDestinationSlackDigestChannel)
	require.NoError(t, err)
	assert.Equal(t, DeliveryChannelSlack, destination.Channel)
	assert.Equal(t, "C-DIGEST", destination.Address)
	assert.Equal(t, SlackTargetChannel, destination.Attributes["target_type"])
}

func TestResolverListSubscribedUsers(t *testing.T) {
	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:    "user-1",
				Email: "alice@example.com",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeEvidenceDigest,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
			"user-2": {
				ID:    "user-2",
				Email: "bob@example.com",
				Subscriptions: []UserSubscription{
					{
						NotificationType: NotificationTypeRiskNotifications,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, nil)

	users, err := resolver.ListSubscribedUsers(context.Background(), Definition{
		Kind:              Kind("evidence_digest"),
		SubscriptionType:  NotificationTypeEvidenceDigest,
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(context.Context, any) (EmailContent, error) {
				return EmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "user-1", users[0].ID)
}
