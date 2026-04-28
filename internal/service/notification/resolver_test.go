package notification

import (
	"context"
	"sort"
	"testing"

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

func (r stubUserRepository) ListActiveUsersBySubscriptionGate(_ context.Context, notificationType string) ([]User, error) {
	if r.err != nil {
		return nil, r.err
	}

	canonicalType, ok := NormalizeSubscriptionGate(notificationType)
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

func (r stubUserRepository) ListActiveUsers(_ context.Context) ([]User, error) {
	if r.err != nil {
		return nil, r.err
	}

	users := make([]User, 0, len(r.users))
	for _, user := range r.users {
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
				Identities: map[string]map[string]string{
					DeliveryChannelEmail: {"email": "user@example.com"},
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

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("risk_review_due"),
		Audiences: []Audience{
			{User: &UserAudience{UserID: "user-1"}},
		},
	}, Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionGate:  SubscriptionGateRiskNotifications,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
				return map[string]string{"text": "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, DeliveryChannelEmail, targets[0].Provider)
	assert.Equal(t, "user@example.com", targets[0].Address["email"])
}

func TestResolverResolveDirectAudienceBypassesSubscriptionsByDesign(t *testing.T) {
	resolver := NewResolver(nil, nil, nil)

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("forgot_password"),
		Audiences: []Audience{
			{Direct: &DirectAudience{Provider: DeliveryChannelEmail, Address: map[string]string{"email": "reset@example.com"}}},
		},
	}, Definition{
		Kind:              Kind("forgot_password"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, DeliveryChannelEmail, targets[0].Provider)
	assert.Equal(t, "reset@example.com", targets[0].Address["email"])
}

func TestResolverResolveUserAudienceSupportsUngatedDefinitions(t *testing.T) {
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
						NotificationType: SubscriptionGateTaskAvailable,
						Channels:         []string{DeliveryChannelSlack},
					},
				},
			},
		},
	}, nil, nil)

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("workflow_execution_failed"),
		Audiences: []Audience{
			{User: &UserAudience{UserID: "user-1"}},
		},
	}, Definition{
		Kind:              Kind("workflow_execution_failed"),
		SubscriptionGate:  SubscriptionGateUngated,
		SupportedChannels: []string{DeliveryChannelEmail, DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
				return map[string]string{"text": "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 2)
	assert.Equal(t, DeliveryChannelEmail, targets[0].Provider)
	assert.Equal(t, "user@example.com", targets[0].Address["email"])
	assert.Equal(t, DeliveryChannelSlack, targets[1].Provider)
	assert.Equal(t, "U123", targets[1].Address["channel"])
}

func TestResolverResolveDirectAudienceUsesExplicitSlackTargetType(t *testing.T) {
	resolver := NewResolver(nil, nil, nil)

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("system_alert"),
		Audiences: []Audience{
			{Direct: &DirectAudience{Provider: DeliveryChannelSlack, Address: map[string]string{"channel": "U123", "target_type": "direct_message"}}},
		},
	}, Definition{
		Kind:              Kind("system_alert"),
		SupportedChannels: []string{DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
				return map[string]string{"text": "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "U123", targets[0].Address["channel"])
	targetType, ok := targets[0].Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, "direct_message", targetType)
}

func TestResolverResolveConfiguredDestinationAudience(t *testing.T) {
	resolver := NewResolver(nil, stubConfiguredDestinationResolver{
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

	targets, err := resolver.Resolve(context.Background(), Request{
		Kind: Kind("evidence_digest"),
		Audiences: []Audience{
			{ConfiguredDestination: &ConfiguredDestinationAudience{Key: "slack.digest_channel"}},
		},
	}, Definition{
		Kind:              Kind("evidence_digest"),
		SupportedChannels: []string{DeliveryChannelSlack},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelSlack: ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
				return map[string]string{"text": "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, targets, 1)
	assert.Equal(t, "C-DIGEST", targets[0].Address["channel"])
	targetType, ok := targets[0].Attribute("target_type")
	require.True(t, ok)
	assert.Equal(t, "channel", targetType)
}

func TestResolverListSubscribedUsers(t *testing.T) {
	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:    "user-1",
				Email: "alice@example.com",
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
			"user-2": {
				ID:    "user-2",
				Email: "bob@example.com",
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateRiskNotifications,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, nil, nil)

	users, err := resolver.ListSubscribedUsers(context.Background(), Definition{
		Kind:              Kind("evidence_digest"),
		SubscriptionGate:  SubscriptionGateEvidenceDigest,
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "user-1", users[0].ID)
}

func TestResolverListSubscribedUsersSupportsUngatedDefinitions(t *testing.T) {
	resolver := NewResolver(stubUserRepository{
		users: map[string]User{
			"user-1": {
				ID:    "user-1",
				Email: "alice@example.com",
			},
			"user-2": {
				ID:    "user-2",
				Email: "bob@example.com",
				Subscriptions: []UserSubscription{
					{
						NotificationType: SubscriptionGateRiskNotifications,
						Channels:         []string{DeliveryChannelEmail},
					},
				},
			},
		},
	}, nil, nil)

	users, err := resolver.ListSubscribedUsers(context.Background(), Definition{
		Kind:              Kind("workflow_execution_failed"),
		SubscriptionGate:  SubscriptionGateUngated,
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "user-1", users[0].ID)
	assert.Equal(t, "user-2", users[1].ID)
}
