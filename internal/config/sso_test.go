package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSSOConfigValidate_ClientSecret(t *testing.T) {
	tests := []struct {
		name     string
		provider SSOProviderConfig
		wantErr  string
	}{
		{
			name:     "confidential client with secret",
			provider: SSOProviderConfig{Name: "dex", Protocol: "oidc", ClientID: "ccf", ClientSecret: "s3cret", Enabled: true},
		},
		{
			name:     "confidential client without secret",
			provider: SSOProviderConfig{Name: "dex", Protocol: "oidc", ClientID: "ccf", Enabled: true},
			wantErr:  `provider "dex" is enabled but client_secret is empty`,
		},
		{
			name:     "public oidc client without secret",
			provider: SSOProviderConfig{Name: "dex", Protocol: "oidc", ClientID: "ccf", PublicClient: true, Enabled: true},
		},
		{
			name:     "public client defaults to oidc when protocol is empty",
			provider: SSOProviderConfig{Name: "dex", ClientID: "ccf", PublicClient: true, Enabled: true},
		},
		{
			name:     "public client with oauth protocol",
			provider: SSOProviderConfig{Name: "github", Protocol: "oauth", ClientID: "ccf", PublicClient: true, Enabled: true},
			wantErr:  `provider "github" sets public_client but uses protocol "oauth"`,
		},
		{
			name:     "public client with a secret",
			provider: SSOProviderConfig{Name: "dex", Protocol: "oidc", ClientID: "ccf", ClientSecret: "s3cret", PublicClient: true, Enabled: true},
			wantErr:  `provider "dex" sets public_client but also sets client_secret`,
		},
		{
			name:     "public client still requires client_id",
			provider: SSOProviderConfig{Name: "dex", Protocol: "oidc", PublicClient: true, Enabled: true},
			wantErr:  `provider "dex" is enabled but client_id is empty`,
		},
		{
			name:     "disabled provider is not validated",
			provider: SSOProviderConfig{Name: "github", Protocol: "oauth", PublicClient: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &SSOConfig{
				Enabled:   true,
				Providers: map[string]SSOProviderConfig{tt.provider.Name: tt.provider},
			}

			err := cfg.validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestLoadSSOConfig_PublicClient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sso.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
enabled: true
callback_url: "http://localhost:8080/api/auth/sso/callback"
providers:
  dex:
    name: "dex"
    provider: "generic"
    protocol: "oidc"
    client_id: "ccf"
    public_client: true
    issuer_url: "http://localhost:5556/dex"
    enabled: true
`), 0o600))

	cfg, err := LoadSSOConfig(path)
	require.NoError(t, err)
	provider := cfg.GetProvider("dex")
	require.NotNil(t, provider)
	require.True(t, provider.PublicClient)
	require.Empty(t, provider.ClientSecret)
}
