package config

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLoadAIConfigDefaults(t *testing.T) {
	v := viper.New()

	cfg, err := LoadAIConfigFromViper(v)

	require.NoError(t, err)
	require.False(t, cfg.Enabled)
	require.Equal(t, AIProviderAnthropic, cfg.Provider)
	require.Equal(t, DefaultAIModel, cfg.Model)
	require.Equal(t, 120*time.Second, cfg.RequestTimeout)
	require.Equal(t, 40, cfg.MaxControlsPerChunk)
	require.Equal(t, 200, cfg.MaxLabelSetsPerChunk)
	require.Equal(t, 4, cfg.QueueWorkers)
	require.Equal(t, 0, cfg.MaxCallsPerRun)
	require.Equal(t, 500, cfg.MaxSuggestionsPerRun)
	require.Empty(t, cfg.APIKey)
}

func TestLoadAIConfigRejectsUnsupportedProvider(t *testing.T) {
	v := viper.New()
	v.Set("ai_enabled", true)
	v.Set("ai_provider", "openai")

	cfg, err := LoadAIConfigFromViper(v)

	require.Nil(t, cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CCF_AI_PROVIDER")
}

func TestLoadAIConfigAllowsUnsupportedProviderWhenDisabled(t *testing.T) {
	v := viper.New()
	v.Set("ai_enabled", false)
	v.Set("ai_provider", "openai")

	cfg, err := LoadAIConfigFromViper(v)

	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.False(t, cfg.Enabled)
	require.Equal(t, "openai", cfg.Provider)
}

func TestAIConfigRedactsAPIKeyFromStringifiedAndJSONOutput(t *testing.T) {
	cfg := &AIConfig{
		Enabled:              true,
		Provider:             AIProviderAnthropic,
		APIKey:               "secret-test-key",
		Model:                DefaultAIModel,
		RequestTimeout:       120 * time.Second,
		MaxControlsPerChunk:  40,
		MaxLabelSetsPerChunk: 200,
		QueueWorkers:         4,
		MaxSuggestionsPerRun: 500,
	}

	stringified := fmt.Sprintf("%v %+v %#v %s", cfg, cfg, cfg, cfg)
	require.NotContains(t, stringified, "secret-test-key")
	require.Contains(t, stringified, "<redacted>")

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "secret-test-key")
	require.NotContains(t, string(raw), "api_key")
}
