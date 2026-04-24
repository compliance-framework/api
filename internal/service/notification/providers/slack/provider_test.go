package slack

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/notification"
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
