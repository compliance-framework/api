package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type OIDCProviderConfig struct {
	Name                string              `yaml:"name" json:"name"`
	DisplayName         string              `yaml:"display_name" json:"displayName"`
	Type                string              `yaml:"type" json:"type"` // oidc (default) or oauth
	IconURL             string              `yaml:"icon_url" json:"iconUrl"`
	RequiredLoginGroups []string            `yaml:"required_login_groups" json:"requiredLoginGroups"`
	RequiredAdminGroups []string            `yaml:"required_admin_groups" json:"requiredAdminGroups"`
	ClientID            string              `yaml:"client_id" json:"clientId"`
	ClientSecret        string              `yaml:"client_secret" json:"clientSecret"`
	IssuerURL           string              `yaml:"issuer_url" json:"issuerUrl"`
	AuthURL             string              `yaml:"auth_url" json:"authUrl"`
	TokenURL            string              `yaml:"token_url" json:"tokenUrl"`
	UserInfoURL         string              `yaml:"user_info_url" json:"userInfoUrl"`
	EmailURL            string              `yaml:"email_url" json:"emailUrl"`
	Scopes              []string            `yaml:"scopes" json:"scopes"`
	Enabled             bool                `yaml:"enabled" json:"enabled"`
	GroupMapping        map[string][]string `yaml:"group_mapping" json:"groupMapping"`
}

type OIDCConfig struct {
	Enabled     bool                 `yaml:"enabled" json:"enabled"`
	BaseURL     string               `yaml:"base_url" json:"baseUrl"`
	CallbackURL string               `yaml:"callback_url" json:"callbackUrl"`
	Providers   []OIDCProviderConfig `yaml:"providers" json:"providers"`
}

func LoadOIDCConfig(path string) (*OIDCConfig, error) {
	if path == "" {
		return &OIDCConfig{Enabled: false}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &OIDCConfig{Enabled: false}, nil
		}
		return nil, fmt.Errorf("failed to read OIDC config file: %w", err)
	}

	var config OIDCConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC config file: %w", err)
	}

	config.expandEnvVars()

	return &config, nil
}

func (c *OIDCConfig) expandEnvVars() {
	c.BaseURL = os.ExpandEnv(c.BaseURL)
	c.CallbackURL = os.ExpandEnv(c.CallbackURL)

	for i := range c.Providers {
		c.Providers[i].ClientID = os.ExpandEnv(c.Providers[i].ClientID)
		c.Providers[i].ClientSecret = os.ExpandEnv(c.Providers[i].ClientSecret)
		c.Providers[i].IssuerURL = os.ExpandEnv(c.Providers[i].IssuerURL)
		c.Providers[i].IconURL = os.ExpandEnv(c.Providers[i].IconURL)
		for j := range c.Providers[i].RequiredLoginGroups {
			c.Providers[i].RequiredLoginGroups[j] = os.ExpandEnv(c.Providers[i].RequiredLoginGroups[j])
		}
		for j := range c.Providers[i].RequiredAdminGroups {
			c.Providers[i].RequiredAdminGroups[j] = os.ExpandEnv(c.Providers[i].RequiredAdminGroups[j])
		}
		c.Providers[i].AuthURL = os.ExpandEnv(c.Providers[i].AuthURL)
		c.Providers[i].TokenURL = os.ExpandEnv(c.Providers[i].TokenURL)
		c.Providers[i].UserInfoURL = os.ExpandEnv(c.Providers[i].UserInfoURL)
		c.Providers[i].EmailURL = os.ExpandEnv(c.Providers[i].EmailURL)
	}
}

func (c *OIDCConfig) GetProvider(name string) *OIDCProviderConfig {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

func (c *OIDCConfig) GetEnabledProviders() []OIDCProviderConfig {
	var enabled []OIDCProviderConfig
	for _, p := range c.Providers {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}
	return enabled
}
