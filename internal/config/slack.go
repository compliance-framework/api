package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type SlackConfig struct {
	Enabled       bool   `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	Token         string `mapstructure:"token" yaml:"token" json:"token"`
	DigestChannel string `mapstructure:"digest_channel" yaml:"digest_channel" json:"digest_channel"`
}

func LoadSlackConfig(path string) (*SlackConfig, error) {
	if path == "" {
		return &SlackConfig{Enabled: false}, nil
	}

	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CCF_SLACK")
	v.SetEnvKeyReplacer(strings.NewReplacer("::", "_", ".", "_", "-", "_"))
	v.AutomaticEnv()

	// Register keys so env-only values are visible to Unmarshal.
	v.SetDefault("enabled", false)
	v.SetDefault("token", "")
	v.SetDefault("digest_channel", "")

	if err := v.BindEnv("enabled"); err != nil {
		return nil, fmt.Errorf("failed to bind slack enabled env var: %w", err)
	}
	if err := v.BindEnv("token"); err != nil {
		return nil, fmt.Errorf("failed to bind slack token env var: %w", err)
	}
	if err := v.BindEnv("digest_channel"); err != nil {
		return nil, fmt.Errorf("failed to bind slack digest_channel env var: %w", err)
	}

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("failed to read slack config file: %w", err)
		}
	}

	var config SlackConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to parse slack config file: %w", err)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *SlackConfig) validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.Token == "" {
		return fmt.Errorf("slack token is required when slack is enabled")
	}

	return nil
}
