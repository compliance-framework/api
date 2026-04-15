package notification

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryRegisterNormalizesDefinition(t *testing.T) {
	registry, err := NewRegistry(Definition{
		Kind:              Kind("risk_review_due"),
		SubscriptionType:  " riskNotifications ",
		SupportedChannels: []string{" Slack ", "email", "slack"},
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

	definition, ok := registry.Definition(Kind("risk_review_due"))
	require.True(t, ok)
	assert.Equal(t, NotificationTypeRiskNotifications, definition.SubscriptionType)
	assert.Equal(t, []string{DeliveryChannelEmail, DeliveryChannelSlack}, definition.SupportedChannels)
}

func TestRegistryRegisterRejectsDuplicateKind(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	definition := Definition{
		Kind:              Kind("workflow_task_assigned"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: EmailChannelRenderer(func(context.Context, any) (EmailContent, error) {
				return EmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	}

	require.NoError(t, registry.Register(definition))
	err = registry.Register(definition)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}
