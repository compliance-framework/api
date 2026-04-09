package slack

import (
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNewService_WithToken_InitializesClient(t *testing.T) {
	service, err := NewService(&config.SlackConfig{
		Enabled: true,
		Token:   "xoxb-test-token",
	}, zap.NewNop().Sugar())

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.NotNil(t, service.client)
}

func TestNewService_WithoutToken_DoesNotInitializeClient(t *testing.T) {
	service, err := NewService(&config.SlackConfig{
		Enabled: true,
		Token:   "",
	}, zap.NewNop().Sugar())

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Nil(t, service.client)
}
