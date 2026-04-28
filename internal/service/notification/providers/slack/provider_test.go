package slack

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTargetDefaultsToChannelTargetType(t *testing.T) {
	provider := NewProvider(nil, nil)

	target, err := provider.BuildTarget(" ccf-alerts ")
	require.NoError(t, err)
	assert.Equal(t, ChannelID, target.Provider)
	assert.Equal(t, "ccf-alerts", target.Address[AddressKeyChannel])
	assert.Equal(t, TargetTypeChannel, target.Address[AddressKeyTargetType])
}

func TestDisplayTargetReturnsNormalizedChannel(t *testing.T) {
	provider := NewProvider(nil, nil)

	channel, err := provider.DisplayTarget(notification.Target{
		Provider: ChannelID,
		Address: map[string]string{
			AddressKeyChannel:    " ccf-alerts ",
			AddressKeyTargetType: " channel ",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "ccf-alerts", channel)
}

func TestProviderMetadataIncludesWorkspaceDetails(t *testing.T) {
	provider := NewProvider(
		nil,
		nil,
		WithEnabledResolver(func() bool { return true }),
		WithWorkspaceConfigurationResolver(func(context.Context) (slacksvc.WorkspaceConfiguration, error) {
			return slacksvc.WorkspaceConfiguration{
				WorkspaceName:   "Acme Security",
				WorkspaceURL:    "https://acme.slack.com/",
				WorkspaceDomain: "acme",
				EmailDomain:     "acme.example.com",
				TeamID:          "T123",
				BotID:           "B123",
				BotName:         "Compliance Bot",
				EnterpriseID:    "E123",
			}, nil
		}),
	)

	metadata := provider.ProviderMetadata()
	assert.Equal(t, "Configured Slack workspace Acme Security", metadata.Description)
	assert.True(t, metadata.Enabled)
	assert.Equal(t, "Acme Security", metadata.Metadata[MetadataKeyWorkspaceName])
	assert.Equal(t, "https://acme.slack.com/", metadata.Metadata[MetadataKeyWorkspaceURL])
	assert.Equal(t, "acme", metadata.Metadata[MetadataKeyWorkspaceDomain])
	assert.Equal(t, "acme.example.com", metadata.Metadata[MetadataKeyEmailDomain])
	assert.Equal(t, "T123", metadata.Metadata[MetadataKeyTeamID])
	assert.Equal(t, "B123", metadata.Metadata[MetadataKeyBotID])
	assert.Equal(t, "Compliance Bot", metadata.Metadata[MetadataKeyBotName])
	assert.Equal(t, "E123", metadata.Metadata[MetadataKeyEnterpriseID])
}

func TestProviderMetadataRetriesWorkspaceDetailsAfterResolverError(t *testing.T) {
	attempts := 0
	provider := NewProvider(
		nil,
		nil,
		WithWorkspaceConfigurationResolver(func(context.Context) (slacksvc.WorkspaceConfiguration, error) {
			attempts++
			if attempts == 1 {
				return slacksvc.WorkspaceConfiguration{}, errors.New("temporary slack failure")
			}

			return slacksvc.WorkspaceConfiguration{
				WorkspaceName: "Recovered Workspace",
				TeamID:        "T456",
			}, nil
		}),
	)

	firstMetadata := provider.ProviderMetadata()
	assert.Equal(t, "Configured Slack workspace", firstMetadata.Description)
	assert.Empty(t, firstMetadata.Metadata)

	secondMetadata := provider.ProviderMetadata()
	assert.Equal(t, "Configured Slack workspace Recovered Workspace", secondMetadata.Description)
	assert.Equal(t, "Recovered Workspace", secondMetadata.Metadata[MetadataKeyWorkspaceName])
	assert.Equal(t, "T456", secondMetadata.Metadata[MetadataKeyTeamID])
	assert.Equal(t, 2, attempts)

	provider.ProviderMetadata()
	assert.Equal(t, 2, attempts)
}

func TestNewCatalogProviderCachesEmptyWorkspaceConfigurationWhenSlackDisabled(t *testing.T) {
	provider := NewCatalogProvider(&config.Config{
		Slack: &config.SlackConfig{
			Enabled: false,
			Token:   "xoxb-test-token",
		},
	})

	metadata := provider.ProviderMetadata()
	assert.False(t, metadata.Enabled)
	assert.Equal(t, "Configured Slack workspace", metadata.Description)
	assert.Empty(t, metadata.Metadata)
	assert.True(t, provider.workspaceConfigurationLoaded)

	provider.ProviderMetadata()
	assert.True(t, provider.workspaceConfigurationLoaded)
}

func TestProviderMetadataIncludesEnabledStateFromResolver(t *testing.T) {
	provider := NewProvider(
		nil,
		nil,
		WithEnabledResolver(func() bool { return true }),
	)

	metadata := provider.ProviderMetadata()
	assert.True(t, metadata.Enabled)
}

func TestDisplayTargetRejectsInvalidSlackTarget(t *testing.T) {
	provider := NewProvider(nil, nil)

	_, err := provider.DisplayTarget(notification.Target{
		Provider: ChannelID,
		Address: map[string]string{
			AddressKeyChannel: "ccf-alerts",
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, notification.ErrInvalidTarget)
}
