package notification

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDefinitionBuildsSupportedChannelsAndRenderers(t *testing.T) {
	definition := NewDefinition(
		Kind("workflow_task_assigned"),
		" taskAvailable ",
		BindRenderer(" email ", ProviderRenderer(DeliveryChannelEmail, func(context.Context, any) (any, error) {
			return testEmailContent{From: "from@example.com", Subject: "subject", TextBody: "body"}, nil
		})),
		BindRenderer(" slack ", ProviderRenderer(DeliveryChannelSlack, func(context.Context, any) (any, error) {
			return map[string]string{"text": "body"}, nil
		})),
	)

	require.NoError(t, definition.Validate())
	assert.Equal(t, []string{"email", "slack"}, definition.SupportedChannels)
	assert.Contains(t, definition.Renderers, "email")
	assert.Contains(t, definition.Renderers, "slack")
	assert.Equal(t, " taskAvailable ", definition.SubscriptionGate)
}
