package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/viper"
)

type OIDCProviderConfig struct {
	Name                string              `yaml:"name" json:"name" mapstructure:"name"`
	DisplayName         string              `yaml:"display_name" json:"displayName" mapstructure:"display_name"`
	Type                string              `yaml:"type" json:"type" mapstructure:"type"` // oidc (default) or oauth
	IconURL             string              `yaml:"icon_url" json:"iconUrl" mapstructure:"icon_url"`
	RequiredLoginGroups []string            `yaml:"required_login_groups" json:"requiredLoginGroups" mapstructure:"required_login_groups"`
	RequiredAdminGroups []string            `yaml:"required_admin_groups" json:"requiredAdminGroups" mapstructure:"required_admin_groups"`
	ClientID            string              `yaml:"client_id" json:"clientId" mapstructure:"client_id"`
	ClientSecret        string              `yaml:"client_secret" json:"clientSecret" mapstructure:"client_secret"`
	IssuerURL           string              `yaml:"issuer_url" json:"issuerUrl" mapstructure:"issuer_url"`
	AuthURL             string              `yaml:"auth_url" json:"authUrl" mapstructure:"auth_url"`
	TokenURL            string              `yaml:"token_url" json:"tokenUrl" mapstructure:"token_url"`
	UserInfoURL         string              `yaml:"user_info_url" json:"userInfoUrl" mapstructure:"user_info_url"`
	EmailURL            string              `yaml:"email_url" json:"emailUrl" mapstructure:"email_url"`
	Scopes              []string            `yaml:"scopes" json:"scopes" mapstructure:"scopes"`
	Enabled             bool                `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	GroupMapping        map[string][]string `yaml:"group_mapping" json:"groupMapping" mapstructure:"group_mapping"`
}

type OIDCConfig struct {
	Enabled     bool                 `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	BaseURL     string               `yaml:"base_url" json:"base_url" mapstructure:"base_url"`
	CallbackURL string               `yaml:"callback_url" json:"callback_url" mapstructure:"callback_url"`
	Providers   []OIDCProviderConfig `yaml:"providers" json:"providers" mapstructure:"providers"`
}

func LoadOIDCConfig(path string) (*OIDCConfig, error) {
	if path == "" {
		return &OIDCConfig{Enabled: false}, nil
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	v.SetEnvPrefix("CCF_OIDC")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			return &OIDCConfig{Enabled: false}, nil
		}
		return nil, fmt.Errorf("failed to read OIDC config file: %w", err)
	}

	var config OIDCConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC config file: %w", err)
	}

	if err := config.expandEnvVars(); err != nil {
		return nil, err
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *OIDCConfig) expandEnvVars() error {
	var errs []string

	var err error
	if c.BaseURL, err = expandStringWithEnv(c.BaseURL); err != nil {
		errs = append(errs, fmt.Sprintf("base_url: %v", err))
	}
	if c.CallbackURL, err = expandStringWithEnv(c.CallbackURL); err != nil {
		errs = append(errs, fmt.Sprintf("callback_url: %v", err))
	}

	for i := range c.Providers {
		providerName := c.Providers[i].Name

		if c.Providers[i].ClientID, err = expandStringWithEnv(c.Providers[i].ClientID); err != nil {
			errs = append(errs, fmt.Sprintf("%s.client_id: %v", providerName, err))
		}
		if c.Providers[i].ClientSecret, err = expandStringWithEnv(c.Providers[i].ClientSecret); err != nil {
			errs = append(errs, fmt.Sprintf("%s.client_secret: %v", providerName, err))
		}
		if c.Providers[i].IssuerURL, err = expandStringWithEnv(c.Providers[i].IssuerURL); err != nil {
			errs = append(errs, fmt.Sprintf("%s.issuer_url: %v", providerName, err))
		}
		if c.Providers[i].IconURL, err = expandStringWithEnv(c.Providers[i].IconURL); err != nil {
			errs = append(errs, fmt.Sprintf("%s.icon_url: %v", providerName, err))
		}

		for j := range c.Providers[i].RequiredLoginGroups {
			if c.Providers[i].RequiredLoginGroups[j], err = expandStringWithEnv(c.Providers[i].RequiredLoginGroups[j]); err != nil {
				errs = append(errs, fmt.Sprintf("%s.required_login_groups[%d]: %v", providerName, j, err))
			}
		}
		for j := range c.Providers[i].RequiredAdminGroups {
			if c.Providers[i].RequiredAdminGroups[j], err = expandStringWithEnv(c.Providers[i].RequiredAdminGroups[j]); err != nil {
				errs = append(errs, fmt.Sprintf("%s.required_admin_groups[%d]: %v", providerName, j, err))
			}
		}

		if c.Providers[i].AuthURL, err = expandStringWithEnv(c.Providers[i].AuthURL); err != nil {
			errs = append(errs, fmt.Sprintf("%s.auth_url: %v", providerName, err))
		}
		if c.Providers[i].TokenURL, err = expandStringWithEnv(c.Providers[i].TokenURL); err != nil {
			errs = append(errs, fmt.Sprintf("%s.token_url: %v", providerName, err))
		}
		if c.Providers[i].UserInfoURL, err = expandStringWithEnv(c.Providers[i].UserInfoURL); err != nil {
			errs = append(errs, fmt.Sprintf("%s.user_info_url: %v", providerName, err))
		}
		if c.Providers[i].EmailURL, err = expandStringWithEnv(c.Providers[i].EmailURL); err != nil {
			errs = append(errs, fmt.Sprintf("%s.email_url: %v", providerName, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to expand environment variables in OIDC config: %s", strings.Join(errs, "; "))
	}

	return nil
}

func (c *OIDCConfig) validate() error {
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

var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandStringWithEnv(input string) (string, error) {
	if input == "" {
		return input, nil
	}

	matches := envVarPattern.FindAllStringSubmatch(input, -1)
	if len(matches) == 0 {
		return input, nil
	}

	missing := make(map[string]struct{})
	replaced := envVarPattern.ReplaceAllStringFunc(input, func(token string) string {
		match := envVarPattern.FindStringSubmatch(token)
		if len(match) != 2 {
			return ""
		}
		key := match[1]
		if val, ok := lookupEnvWithPrefix(key); ok {
			return val
		}
		missing[key] = struct{}{}
		return ""
	})

	if len(missing) > 0 {
		var names []string
		for k := range missing {
			names = append(names, k)
		}
		sort.Strings(names)
		return "", fmt.Errorf("missing environment variables: %s", strings.Join(names, ", "))
	}

	return replaced, nil
}

func lookupEnvWithPrefix(key string) (string, bool) {
	if val, ok := os.LookupEnv(key); ok {
		return val, true
	}
	prefixed := fmt.Sprintf("CCF_%s", key)
	if val, ok := os.LookupEnv(prefixed); ok {
		return val, true
	}
	return "", false
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
