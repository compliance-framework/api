package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadPlaybackConfigDefaults(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	cfg := LoadPlaybackConfig()

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 5*time.Second, cfg.Timeout)
	assert.Equal(t, int64(2<<20), cfg.MaxBytes)
	assert.Equal(t, 4, cfg.MaxConcurrent)
}

func TestLoadPlaybackConfigOverrides(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("playback_enabled", false)
	viper.Set("playback_timeout", "250ms")
	viper.Set("playback_max_bytes", 1024)
	viper.Set("playback_max_concurrent", 1)

	cfg := LoadPlaybackConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, 250*time.Millisecond, cfg.Timeout)
	assert.Equal(t, int64(1024), cfg.MaxBytes)
	assert.Equal(t, 1, cfg.MaxConcurrent)
}

func TestLoadPlaybackConfigIgnoresNonPositiveValues(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("playback_timeout", "0s")
	viper.Set("playback_max_bytes", -1)
	viper.Set("playback_max_concurrent", 0)

	cfg := LoadPlaybackConfig()

	assert.Equal(t, DefaultPlaybackConfig(), cfg)
}

func TestLoadArtifactConfig(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	assert.Equal(t, int64(16<<20), LoadArtifactConfig().MaxBytes)

	assert.Equal(t, 8, LoadArtifactConfig().MaxConcurrent)

	viper.Set("artifact_max_bytes", 1024)
	viper.Set("artifact_max_concurrent", 2)
	assert.Equal(t, int64(1024), LoadArtifactConfig().MaxBytes)
	assert.Equal(t, 2, LoadArtifactConfig().MaxConcurrent)

	viper.Set("artifact_max_bytes", -1)
	viper.Set("artifact_max_concurrent", 0)
	assert.Equal(t, DefaultArtifactConfig(), LoadArtifactConfig())
}
