package config

import (
	"time"

	"github.com/spf13/viper"
)

// PlaybackConfig controls POST /api/playback/evaluate, which runs caller-supplied Rego in
// the API process.
type PlaybackConfig struct {
	// Enabled registers the route. CCF_PLAYBACK_ENABLED, default true.
	Enabled bool `json:"enabled"`
	// Timeout bounds one evaluation. CCF_PLAYBACK_TIMEOUT, default 5s.
	Timeout time.Duration `json:"timeout"`
	// MaxBytes bounds the request body. CCF_PLAYBACK_MAX_BYTES, default 2 MiB.
	MaxBytes int64 `json:"maxBytes"`
	// MaxConcurrent bounds evaluations running at once across all callers; extra requests
	// get 429. CCF_PLAYBACK_MAX_CONCURRENT, default 4.
	MaxConcurrent int `json:"maxConcurrent"`
}

func DefaultPlaybackConfig() *PlaybackConfig {
	return &PlaybackConfig{
		Enabled:       true,
		Timeout:       5 * time.Second,
		MaxBytes:      2 << 20,
		MaxConcurrent: 4,
	}
}

// LoadPlaybackConfig reads CCF_PLAYBACK_* settings, falling back to the default for any
// value that is unset or not positive.
func LoadPlaybackConfig() *PlaybackConfig {
	cfg := DefaultPlaybackConfig()
	if viper.IsSet("playback_enabled") {
		cfg.Enabled = viper.GetBool("playback_enabled")
	}
	if timeout := viper.GetDuration("playback_timeout"); timeout > 0 {
		cfg.Timeout = timeout
	}
	if maxBytes := viper.GetInt64("playback_max_bytes"); maxBytes > 0 {
		cfg.MaxBytes = maxBytes
	}
	if maxConcurrent := viper.GetInt("playback_max_concurrent"); maxConcurrent > 0 {
		cfg.MaxConcurrent = maxConcurrent
	}
	return cfg
}
