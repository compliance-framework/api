package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

// EmailProviderSettings represents common behaviors for all provider-specific configs.
type EmailProviderSettings interface {
	GetName() string
	GetType() string
	IsEnabled() bool
}

type EmailConfig struct {
	Enabled   bool                     `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Provider  string                   `yaml:"provider" json:"provider" mapstructure:"provider"` // default provider to use
	Providers *SupportedEmailProviders `yaml:"providers" json:"providers" mapstructure:"providers"`
}

type SupportedEmailProviders struct {
	SMTP *SMTPConfig `yaml:"smtp" json:"smtp" mapstructure:"smtp"`
	SES  *SESConfig  `yaml:"ses" json:"ses" mapstructure:"ses"`
}

type SMTPConfig struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Enabled  bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Host     string `yaml:"host" json:"host" mapstructure:"host"`
	Port     int    `yaml:"port" json:"port" mapstructure:"port"`
	Username string `yaml:"username" json:"username" mapstructure:"username"`
	Password string `yaml:"password" json:"password" mapstructure:"password"`
	From     string `yaml:"from" json:"from" mapstructure:"from"`
	FromName string `yaml:"from_name" json:"fromName" mapstructure:"from_name"`
	UseTLS   bool   `yaml:"use_tls" json:"useTls" mapstructure:"use_tls"`
	UseSSL   bool   `yaml:"use_ssl" json:"useSsl" mapstructure:"use_ssl"`
}

type SESConfig struct {
	Name            string `yaml:"name" json:"name" mapstructure:"name"`
	Enabled         bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	Region          string `yaml:"region" json:"region" mapstructure:"region"`
	AccessKeyID     string `yaml:"access_key_id" json:"accessKeyId" mapstructure:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key" json:"secretAccessKey" mapstructure:"secret_access_key"`
	From            string `yaml:"from" json:"from" mapstructure:"from"`
	FromName        string `yaml:"from_name" json:"fromName" mapstructure:"from_name"`
}

func LoadEmailConfig(path string) (*EmailConfig, error) {
	if path == "" {
		return &EmailConfig{Enabled: false, Providers: &SupportedEmailProviders{}}, nil
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
			return &EmailConfig{Enabled: false, Providers: &SupportedEmailProviders{}}, nil
		}
		return nil, fmt.Errorf("failed to read email config file: %w", err)
	}

	var config EmailConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to parse email config file: %w", err)
	}
	if config.Providers == nil {
		config.Providers = &SupportedEmailProviders{}
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *EmailConfig) validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.Providers == nil {
		return fmt.Errorf("email is enabled but no providers are configured")
	}

	seenEnabled := false
	for _, provider := range c.Providers.asSlice() {
		if provider == nil || !provider.IsEnabled() {
			continue
		}
		seenEnabled = true
		switch p := provider.(type) {
		case *SMTPConfig:
			if err := p.validate(); err != nil {
				return err
			}
		case *SESConfig:
			if err := p.validate(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown provider type %q", provider.GetType())
		}
	}

	if !seenEnabled {
		return fmt.Errorf("email is enabled but no providers are enabled")
	}

	if strings.TrimSpace(c.Provider) != "" {
		selected := c.GetProvider(c.Provider)
		if selected == nil {
			return fmt.Errorf("default provider %q does not exist", c.Provider)
		}
		if !selected.IsEnabled() {
			return fmt.Errorf("default provider %q is not enabled", c.Provider)
		}
	}

	return nil
}

func (c *EmailConfig) GetProvider(name string) EmailProviderSettings {
	if c == nil || c.Providers == nil {
		return nil
	}

	normalized := strings.ToLower(strings.TrimSpace(name))
	switch normalized {
	case "smtp":
		if c.Providers.SMTP != nil {
			return c.Providers.SMTP
		}
	case "ses":
		if c.Providers.SES != nil {
			return c.Providers.SES
		}
	}

	for _, provider := range c.Providers.asSlice() {
		if provider != nil && strings.EqualFold(provider.GetName(), name) {
			return provider
		}
	}

	return nil
}

func (c *EmailConfig) GetDefaultProvider() EmailProviderSettings {
	if c == nil || !c.Enabled || c.Providers == nil {
		return nil
	}

	if strings.TrimSpace(c.Provider) != "" {
		if p := c.GetProvider(c.Provider); p != nil && p.IsEnabled() {
			return p
		}
	}

	enabled := c.GetEnabledProviders()
	if len(enabled) == 0 {
		return nil
	}

	return enabled[0]
}

func (c *EmailConfig) GetEnabledProviders() []EmailProviderSettings {
	if c == nil || c.Providers == nil {
		return nil
	}

	var enabled []EmailProviderSettings
	for _, provider := range c.Providers.asSlice() {
		if provider != nil && provider.IsEnabled() {
			enabled = append(enabled, provider)
		}
	}

	sort.SliceStable(enabled, func(i, j int) bool {
		return enabled[i].GetType() < enabled[j].GetType()
	})

	return enabled
}

func (p *SupportedEmailProviders) asSlice() []EmailProviderSettings {
	if p == nil {
		return nil
	}
	var providers []EmailProviderSettings
	if p.SMTP != nil {
		providers = append(providers, p.SMTP)
	}
	if p.SES != nil {
		providers = append(providers, p.SES)
	}
	return providers
}

func (c *SMTPConfig) GetName() string {
	if c == nil {
		return ""
	}
	if strings.TrimSpace(c.Name) != "" {
		return c.Name
	}
	return "smtp"
}

func (c *SMTPConfig) GetType() string {
	return "smtp"
}

func (c *SMTPConfig) IsEnabled() bool {
	return c != nil && c.Enabled
}

func (c *SMTPConfig) validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("SMTP provider %q is enabled but host is empty", c.GetName())
	}
	if c.Port <= 0 {
		return fmt.Errorf("SMTP provider %q is enabled but port is invalid", c.GetName())
	}
	if strings.TrimSpace(c.From) == "" {
		return fmt.Errorf("SMTP provider %q is enabled but from address is empty", c.GetName())
	}
	return nil
}

func (c *SESConfig) GetName() string {
	if c == nil {
		return ""
	}
	if strings.TrimSpace(c.Name) != "" {
		return c.Name
	}
	return "ses"
}

func (c *SESConfig) GetType() string {
	return "ses"
}

func (c *SESConfig) IsEnabled() bool {
	return c != nil && c.Enabled
}

func (c *SESConfig) validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if strings.TrimSpace(c.Region) == "" {
		return fmt.Errorf("SES provider %q is enabled but region is empty", c.GetName())
	}
	if strings.TrimSpace(c.From) == "" {
		return fmt.Errorf("SES provider %q is enabled but from address is empty", c.GetName())
	}
	return nil
}
