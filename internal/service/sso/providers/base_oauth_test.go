package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func TestBaseOAuthProvider_GetUserInfo_WithExistingEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo":
			resp := map[string]any{
				"id":         42,
				"email":      "octo@example.com",
				"name":       "Octo Cat",
				"department": []string{"engineering"},
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.SSOProviderConfig{
		Name:        "generic-oauth",
		ClientID:    "client",
		UserInfoURL: server.URL + "/userinfo",
		GroupMapping: map[string][]string{
			"department:engineering": {"ccf-engineering"},
		},
	}

	logger := zap.NewNop().Sugar()
	provider, err := NewBaseOAuthProvider(cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := &oauth2.Token{AccessToken: "token"}
	info, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Equal(t, "42", info.Subject)
	require.Equal(t, "Octo Cat", info.Name)
	require.Equal(t, "Octo", info.FirstName)
	require.Equal(t, "Cat", info.LastName)
	require.Equal(t, "octo@example.com", info.Email)
	require.ElementsMatch(t, []string{"ccf-engineering"}, info.Groups)
}

func TestBaseOAuthProvider_GetUserInfo_EmailFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/userinfo":
			resp := map[string]any{
				"id":   "user-123",
				"name": "Fallback User",
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/emails":
			resp := []map[string]any{
				{"email": "primary@example.com", "primary": true},
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := &config.SSOProviderConfig{
		Name:        "generic-oauth",
		ClientID:    "client",
		UserInfoURL: server.URL + "/userinfo",
		EmailURL:    server.URL + "/emails",
	}

	logger := zap.NewNop().Sugar()
	provider, err := NewBaseOAuthProvider(cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := &oauth2.Token{AccessToken: "token"}
	info, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Equal(t, "user-123", info.Subject)
	require.Equal(t, "primary@example.com", info.Email)
	require.Equal(t, "Fallback", info.FirstName)
	require.Equal(t, "User", info.LastName)
}

func TestBaseOAuthProvider_DoesNotUsePKCE(t *testing.T) {
	cfg := &config.SSOProviderConfig{
		Name:         "generic-oauth",
		ClientID:     "client",
		ClientSecret: "secret",
		AuthURL:      "https://oauth.example.com/authorize",
		TokenURL:     "https://oauth.example.com/token",
	}

	base, err := NewBaseOAuthProvider(cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)
	github, err := NewGitHubOAuthProvider(cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)

	for name, provider := range map[string]interface {
		GetAuthURL(state string, codeVerifier string) string
		UsesPKCE() bool
	}{"generic": base, "github": github} {
		t.Run(name, func(t *testing.T) {
			require.False(t, provider.UsesPKCE())

			authURL, err := url.Parse(provider.GetAuthURL("state123", oauth2.GenerateVerifier()))
			require.NoError(t, err)
			query := authURL.Query()
			require.Equal(t, "state123", query.Get("state"))
			require.Empty(t, query.Get("code_challenge"))
			require.Empty(t, query.Get("code_challenge_method"))
		})
	}
}
