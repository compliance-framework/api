package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type SSOProviderConfig struct {
	Name                string              `yaml:"name" json:"name" mapstructure:"name"`
	DisplayName         string              `yaml:"display_name" json:"displayName" mapstructure:"display_name"`
	Provider            string              `yaml:"provider" json:"provider" mapstructure:"provider"` // google, github, generic
	Protocol            string              `yaml:"protocol" json:"protocol" mapstructure:"protocol"` // oidc or oauth
	IconURL             string              `yaml:"icon_url" json:"iconUrl" mapstructure:"icon_url"`
	RequiredLoginGroups []string            `yaml:"required_login_groups" json:"requiredLoginGroups" mapstructure:"required_login_groups"`
	RequiredAdminGroups []string            `yaml:"required_admin_groups" json:"requiredAdminGroups" mapstructure:"required_admin_groups"`
	ClientID            string              `yaml:"client_id" json:"clientId" mapstructure:"client_id"`
	ClientSecret        string              `yaml:"client_secret" json:"clientSecret" mapstructure:"client_secret"`
	IssuerURL           string              `yaml:"issuer_url" json:"issuerUrl" mapstructure:"issuer_url"`
	WellKnownURL        string              `yaml:"well_known_url" json:"wellKnownUrl" mapstructure:"well_known_url"`
	AuthURL             string              `yaml:"auth_url" json:"authUrl" mapstructure:"auth_url"`
	TokenURL            string              `yaml:"token_url" json:"tokenUrl" mapstructure:"token_url"`
	UserInfoURL         string              `yaml:"user_info_url" json:"userInfoUrl" mapstructure:"user_info_url"`
	EmailURL            string              `yaml:"email_url" json:"emailUrl" mapstructure:"email_url"`
	Scopes              []string            `yaml:"scopes" json:"scopes" mapstructure:"scopes"`
	Enabled             bool                `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	GroupMapping        map[string][]string `yaml:"group_mapping" json:"groupMapping" mapstructure:"group_mapping"`
}

type SSOConfig struct {
	Enabled     bool                         `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	BaseURL     string                       `yaml:"base_url" json:"base_url" mapstructure:"base_url"`
	CallbackURL string                       `yaml:"callback_url" json:"callback_url" mapstructure:"callback_url"`
	Providers   map[string]SSOProviderConfig `yaml:"providers" json:"providers" mapstructure:"providers"`
}

func LoadSSOConfig(path string) (*SSOConfig, error) {
	if path == "" {
		return &SSOConfig{Enabled: false}, nil
	}

	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CCF_SSO")
	v.SetEnvKeyReplacer(strings.NewReplacer("::", "_", ".", "_", "-", "_"))
	v.AutomaticEnv()
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			return &SSOConfig{Enabled: false}, nil
		}
		return nil, fmt.Errorf("failed to read SSO config file: %w", err)
	}
	var config SSOConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to parse SSO config file: %w", err)
	}
	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *SSOConfig) validate() error {
	for _, p := range c.Providers {
		if !p.Enabled {
			continue
		}
		if strings.TrimSpace(p.ClientID) == "" {
			return fmt.Errorf("provider %q is enabled but client_id is empty", p.Name)
		}
		if strings.TrimSpace(p.ClientSecret) == "" {
			return fmt.Errorf("provider %q is enabled but client_secret is empty", p.Name)
		}
	}
	return nil
}

func (c *SSOConfig) GetProvider(name string) *SSOProviderConfig {
	if c == nil {
		return nil
	}
	if p, ok := c.Providers[name]; ok {
		return &p
	}
	return nil
}

func (c *SSOConfig) GetEnabledProviders() []SSOProviderConfig {
	var enabled []SSOProviderConfig
	for _, p := range c.Providers {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	return enabled
}
