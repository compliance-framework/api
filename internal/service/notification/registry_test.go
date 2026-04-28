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
		SubscriptionGate:  " riskNotifications ",
		SupportedChannels: []string{" Slack ", "email", "slack"},
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

	definition, ok := registry.Definition(Kind("risk_review_due"))
	require.True(t, ok)
	assert.Equal(t, SubscriptionGateRiskNotifications, definition.SubscriptionGate)
	assert.Equal(t, []string{DeliveryChannelEmail, DeliveryChannelSlack}, definition.SupportedChannels)
}

func TestRegistryRegisterRejectsDuplicateKind(t *testing.T) {
	registry, err := NewRegistry()
	require.NoError(t, err)

	definition := Definition{
		Kind:              Kind("workflow_task_assigned"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	}

	require.NoError(t, registry.Register(definition))
	err = registry.Register(definition)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

func TestRegistryDefinitionReturnsIndependentRendererMap(t *testing.T) {
	registry, err := NewRegistry(Definition{
		Kind:              Kind("digest"),
		SupportedChannels: []string{DeliveryChannelEmail},
		Renderers: map[string]ChannelRenderer{
			DeliveryChannelEmail: ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
				return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
			}),
		},
	})
	require.NoError(t, err)

	definition, ok := registry.Definition(Kind("digest"))
	require.True(t, ok)
	definition.Renderers[DeliveryChannelEmail] = nil

	reloaded, ok := registry.Definition(Kind("digest"))
	require.True(t, ok)
	assert.NotNil(t, reloaded.Renderers[DeliveryChannelEmail])
}
