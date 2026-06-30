package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/require"
)

// loadProviderConfig writes sso.yaml content to a temp file, loads it through the real
// config.LoadSSOConfig (i.e. through viper, exactly as the running service does) and returns the
// named provider's config.
func loadProviderConfig(t *testing.T, provider, content string) *config.SSOProviderConfig {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sso.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	cfg, err := config.LoadSSOConfig(path)
	require.NoError(t, err)

	p, ok := cfg.Providers[provider]
	require.Truef(t, ok, "provider %q not found in loaded config", provider)
	return &p
}

func TestMapClaimGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mapping map[string][]string
		claims  map[string]any
		want    []string
	}{
		{
			name:    "nil mapping yields nothing",
			mapping: nil,
			claims:  map[string]any{"groups": []any{"admins"}},
			want:    nil,
		},
		{
			name:    "exact match",
			mapping: map[string][]string{"groups:admins": {"ccf-admins"}},
			claims:  map[string]any{"groups": []any{"admins"}},
			want:    []string{"ccf-admins"},
		},
		{
			// The reported bug: the IdP delivers a mixed-case group name while the config key has
			// been lowercased (by viper, or simply written in a different case). The mapping must
			// still resolve.
			name:    "claim group with uppercase still maps to a lowercased config key",
			mapping: map[string][]string{"groups:rappmygroup": {"ccf-users", "ccf-admins"}},
			claims:  map[string]any{"groups": []any{"rAppMyGroup"}},
			want:    []string{"ccf-users", "ccf-admins"},
		},
		{
			name:    "string claim (e.g. hosted domain) maps case-insensitively",
			mapping: map[string][]string{"hd:example.com": {"ccf-hosted"}},
			claims:  map[string]any{"hd": "Example.COM"},
			want:    []string{"ccf-hosted"},
		},
		{
			name: "multiple claim groups, only mapped ones contribute",
			mapping: map[string][]string{
				"groups:engineers": {"ccf-eng"},
				"groups:admins":    {"ccf-admins"},
			},
			claims: map[string]any{"groups": []any{"Engineers", "marketing", "Admins"}},
			want:   []string{"ccf-eng", "ccf-admins"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.ElementsMatch(t, tt.want, mapClaimGroups(tt.mapping, tt.claims))
		})
	}
}

// TestExtractGroups_SurvivesViperKeyLowercasing is the end-to-end regression for the reported bug:
// an Active Directory group name with uppercase letters (rApp...) was never granted because viper
// lowercases every group_mapping key at config load while the IdP claim value keeps its original
// case, and the old lookup was case-sensitive — so the user's groups resolved to an empty set and
// required-login-group enforcement rejected them with groups=[].
func TestExtractGroups_SurvivesViperKeyLowercasing(t *testing.T) {
	t.Parallel()

	cfg := loadProviderConfig(t, "dex", `enabled: true
base_url: "https://ui.example.com"
callback_url: "https://api.example.com/api/auth/sso/callback"
providers:
  dex:
    name: dex
    provider: generic
    protocol: oidc
    enabled: true
    client_id: ccf-app
    client_secret: secret
    issuer_url: "https://auth.example.com"
    required_login_groups:
      - ccf-users
    group_mapping:
      "groups:rAppMyGroup":
        - ccf-users
        - ccf-admins
`)

	// Precondition documenting the root cause: viper has lowercased the configured key, so a
	// case-sensitive lookup with the IdP's original casing can never hit it.
	_, exact := cfg.GroupMapping["groups:rAppMyGroup"]
	require.False(t, exact, "expected viper to lowercase the group_mapping key")
	require.Contains(t, cfg.GroupMapping, "groups:rappmygroup")

	p := &BaseOIDCProvider{config: cfg}

	// Claims as DEX actually delivers them in the ID token: the AD group cn, original case.
	claims := map[string]any{
		"email":  "user@corp.com",
		"groups": []any{"Group1", "Group2", "rAppMyGroup"},
	}

	require.ElementsMatch(t, []string{"ccf-users", "ccf-admins"}, p.extractGroups(claims))
}
