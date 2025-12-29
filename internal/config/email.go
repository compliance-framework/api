package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

type EmailProviderConfig struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Provider string `yaml:"provider" json:"provider" mapstructure:"provider"` // smtp, sendgrid, ses, etc
	Enabled  bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// SMTP Configuration
	// For SES providers, Host stores the AWS region and Username/Password store the AWS access/secret keys.
	Host     string `yaml:"host" json:"host" mapstructure:"host"`
	Port     int    `yaml:"port" json:"port" mapstructure:"port"`
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
	From     string `yaml:"from" json:"from" mapstructure:"from"`
	FromName string `yaml:"from_name" json:"fromName" mapstructure:"from_name"`

	// TLS Configuration
	UseTLS bool `yaml:"use_tls" json:"useTls" mapstructure:"use_tls"`
	UseSSL bool `yaml:"use_ssl" json:"useSsl" mapstructure:"use_ssl"`
}

type EmailConfig struct {
	Enabled   bool                           `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Provider  string                         `yaml:"provider" json:"provider" mapstructure:"provider"` // default provider to use
	Providers map[string]EmailProviderConfig `yaml:"providers" json:"providers" mapstructure:"providers"`
}

func LoadEmailConfig(path string) (*EmailConfig, error) {
	if path == "" {
		return &EmailConfig{Enabled: false}, nil
	}

	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CCF_EMAIL")
	v.SetEnvKeyReplacer(strings.NewReplacer("::", "_", ".", "_", "-", "_"))
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			return &EmailConfig{Enabled: false}, nil
		}
		return nil, fmt.Errorf("failed to read email config file: %w", err)
	}
	var config EmailConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to parse email config file: %w", err)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *EmailConfig) validate() error {
	if !c.Enabled {
		return nil
	}

	for name, p := range c.Providers {
		if !p.Enabled {
			continue
		}

		if strings.TrimSpace(p.Provider) == "" {
			return fmt.Errorf("provider %q is enabled but provider type is empty", name)
		}

		// Validate SMTP provider specific fields
		if strings.ToLower(p.Provider) == "smtp" {
			if strings.TrimSpace(p.Host) == "" {
				return fmt.Errorf("SMTP provider %q is enabled but host is empty", name)
			}
			if p.Port <= 0 {
				return fmt.Errorf("SMTP provider %q is enabled but port is invalid", name)
			}
			if strings.TrimSpace(p.From) == "" {
				return fmt.Errorf("SMTP provider %q is enabled but from address is empty", name)
			}
		}
	}

	// If default provider is specified, ensure it exists and is enabled
	if c.Provider != "" {
		if p, ok := c.Providers[c.Provider]; !ok {
			return fmt.Errorf("default provider %q does not exist", c.Provider)
		} else if !p.Enabled {
			return fmt.Errorf("default provider %q is not enabled", c.Provider)
		}
	}

	return nil
}

func (c *EmailConfig) GetProvider(name string) *EmailProviderConfig {
	if c == nil {
		return nil
	}
	if p, ok := c.Providers[name]; ok {
		return &p
	}
	return nil
}

func (c *EmailConfig) GetDefaultProvider() *EmailProviderConfig {
	if c == nil || !c.Enabled {
		return nil
	}

	// If default provider is specified, use it
	if c.Provider != "" {
		if p := c.GetProvider(c.Provider); p != nil && p.Enabled {
			return p
		}
	}

	// Otherwise, return the first enabled provider in deterministic order
	if len(c.Providers) == 0 {
		return nil
	}

	names := make([]string, 0, len(c.Providers))
	for name := range c.Providers {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		p := c.Providers[name]
		if p.Enabled {
			return &p
		}
	}

	return nil
}

func (c *EmailConfig) GetEnabledProviders() []EmailProviderConfig {
	var enabled []EmailProviderConfig
	for _, p := range c.Providers {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	return enabled
}
