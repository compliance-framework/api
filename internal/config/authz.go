package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// DefaultAuthzDriver is the in-process driver that reproduces CCF's pre-authz rules.
	DefaultAuthzDriver = "builtin"
	// DefaultAuthzFailMode denies requests when the PDP is unavailable.
	DefaultAuthzFailMode = "closed"
)

// AuthzConfig configures the central authorization layer. Driver selects the PDP engine
// ("builtin" in-process, "cedar" the embedded Cedar RBAC engine, or "authzen" for any remote
// AuthZen-compliant PDP); FailMode controls how the PEP behaves when the PDP is unavailable
// ("closed" denies, "open" allows). Endpoint is the remote PDP's single-evaluation URL
// (authzen driver only), and CacheTTL optionally caches decisions for that long to absorb the
// network hop (0 = off).
//
// The cedar driver reads two more (both optional, both ignored by the other drivers):
// RoleAssignmentsPath is the YAML file mapping users/groups/agents to the bundled roles
// (BCH-1319 §11.3); CedarPolicyDir is a directory of operator *.cedar files appended to the
// bundled role policies (the GitOps escape hatch, §11.2).
type AuthzConfig struct {
	Driver              string        `mapstructure:"driver" json:"driver"`
	FailMode            string        `mapstructure:"fail_mode" json:"failMode"`
	Endpoint            string        `mapstructure:"endpoint" json:"endpoint"`
	CacheTTL            time.Duration `mapstructure:"cache_ttl" json:"cacheTtl"`
	RoleAssignmentsPath string        `mapstructure:"role_assignments" json:"roleAssignments"`
	CedarPolicyDir      string        `mapstructure:"cedar_policy_dir" json:"cedarPolicyDir"`
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
	// Endpoint is a URL — keep its original casing, only trim surrounding quotes/space.
	endpoint := strings.TrimSpace(stripQuotes(viper.GetString("authz_endpoint")))
	// Paths keep their original casing (filesystem-sensitive); only trim quotes/space. The
	// role-assignment file defaults to authz-roles.yaml (matching the sso.yaml/risk.yaml
	// convention); a missing file is tolerated by the cedar driver. The cedar policy dir has
	// no default — operator .cedar files are opt-in.
	roleAssignments := strings.TrimSpace(stripQuotes(viper.GetString("authz_role_assignments")))
	if roleAssignments == "" {
		roleAssignments = "authz-roles.yaml"
	}
	return &AuthzConfig{
		Driver:              driver,
		FailMode:            failMode,
		Endpoint:            endpoint,
		CacheTTL:            parseAuthzCacheTTL(stripQuotes(viper.GetString("authz_cache_ttl"))),
		RoleAssignmentsPath: roleAssignments,
		CedarPolicyDir:      strings.TrimSpace(stripQuotes(viper.GetString("authz_cedar_policy_dir"))),
	}
}

// parseAuthzCacheTTL parses a duration string (e.g. "5s"); an empty, invalid, or negative
// value disables the cache (0).
func parseAuthzCacheTTL(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0
	}
	return d
}
