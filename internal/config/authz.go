package config

import (
	"strings"

	"github.com/spf13/viper"
)

const (
	// DefaultAuthzDriver is the in-process driver that reproduces CCF's pre-authz rules.
	DefaultAuthzDriver = "builtin"
	// DefaultAuthzFailMode denies requests when the PDP is unavailable.
	DefaultAuthzFailMode = "closed"
)

// AuthzConfig configures the central authorization layer. Driver selects the PDP engine
// (only "builtin" is implemented in Phase 1); FailMode controls how the PEP behaves when
// the PDP is unavailable ("closed" denies, "open" allows).
type AuthzConfig struct {
	Driver   string `mapstructure:"driver" json:"driver"`
	FailMode string `mapstructure:"fail_mode" json:"failMode"`
}

// LoadAuthzConfig reads authz settings from Viper, applying defaults. Any fail mode other
// than "open" is normalized to the default "closed" so a typo fails safe.
func LoadAuthzConfig() *AuthzConfig {
	driver := strings.ToLower(strings.TrimSpace(stripQuotes(viper.GetString("authz_driver"))))
	if driver == "" {
		driver = DefaultAuthzDriver
	}
	failMode := strings.ToLower(strings.TrimSpace(stripQuotes(viper.GetString("authz_fail_mode"))))
	if failMode != "open" {
		failMode = DefaultAuthzFailMode
	}
	return &AuthzConfig{Driver: driver, FailMode: failMode}
}
