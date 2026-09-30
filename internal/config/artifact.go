package config

import "github.com/spf13/viper"

// ArtifactConfig controls the policy evaluation artifact store.
type ArtifactConfig struct {
	// MaxBytes bounds one uploaded artifact. CCF_ARTIFACT_MAX_BYTES, default 16 MiB.
	MaxBytes int64 `json:"maxBytes"`
}

func DefaultArtifactConfig() *ArtifactConfig {
	return &ArtifactConfig{MaxBytes: 16 << 20}
}

// LoadArtifactConfig reads CCF_ARTIFACT_* settings, falling back to the default for any
// value that is unset or not positive.
func LoadArtifactConfig() *ArtifactConfig {
	cfg := DefaultArtifactConfig()
	if maxBytes := viper.GetInt64("artifact_max_bytes"); maxBytes > 0 {
		cfg.MaxBytes = maxBytes
	}
	return cfg
}
