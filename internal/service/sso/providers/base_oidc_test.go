package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/providers/testutil"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func TestBaseOIDCProvider_GetUserInfo(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	claims := map[string]any{
		"email":       "dev@example.com",
		"name":        "Dev User",
		"given_name":  "Dev",
		"family_name": "User",
		"hd":          "example.com",
		"role":        "admin",
		"department":  "engineering",
	}

	rawIDToken, err := mock.SignIDToken(claims)
	require.NoError(t, err)

	cfg := &config.SSOProviderConfig{
		Name:      "test-oidc",
		ClientID:  "test-client",
		IssuerURL: mock.IssuerURL,
		GroupMapping: map[string][]string{
			"role:admin":             {"ccf-admins"},
			"department:engineering": {"ccf-engineering"},
		},
	}
	logger := zap.NewNop().Sugar()
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := (&oauth2.Token{AccessToken: "token"}).WithExtra(map[string]any{
		"id_token": rawIDToken,
	})

	userInfo, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Equal(t, "test-subject", userInfo.Subject)
	require.Equal(t, "Dev", userInfo.FirstName)
	require.Equal(t, "User", userInfo.LastName)
	require.Equal(t, "Dev User", userInfo.Name)
	require.Equal(t, "dev@example.com", userInfo.Email)
	require.Equal(t, "example.com", userInfo.HostedDomain)

	require.ElementsMatch(t, []string{"ccf-admins", "ccf-engineering"}, userInfo.Groups)
}

func TestBaseOIDCProvider_GetUserInfoSplitsNameWhenStructuredNameMissing(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	claims := map[string]any{
		"email": "alice@example.com",
		"name":  "Alice Dex Admin",
	}

	rawIDToken, err := mock.SignIDToken(claims)
	require.NoError(t, err)

	cfg := &config.SSOProviderConfig{
		Name:      "test-oidc",
		ClientID:  "test-client",
		IssuerURL: mock.IssuerURL,
	}
	logger := zap.NewNop().Sugar()
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := (&oauth2.Token{AccessToken: "token"}).WithExtra(map[string]any{
		"id_token": rawIDToken,
	})

	userInfo, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Equal(t, "Alice Dex Admin", userInfo.Name)
	require.Equal(t, "Alice", userInfo.FirstName)
	require.Equal(t, "Dex Admin", userInfo.LastName)
}

func TestBaseOIDCProvider_GetUserInfoKeepsStructuredNameClaims(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	claims := map[string]any{
		"email":       "dev@example.com",
		"name":        "Display Name",
		"given_name":  "Structured",
		"family_name": "Person",
	}

	rawIDToken, err := mock.SignIDToken(claims)
	require.NoError(t, err)

	cfg := &config.SSOProviderConfig{
		Name:      "test-oidc",
		ClientID:  "test-client",
		IssuerURL: mock.IssuerURL,
	}
	logger := zap.NewNop().Sugar()
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := (&oauth2.Token{AccessToken: "token"}).WithExtra(map[string]any{
		"id_token": rawIDToken,
	})

	userInfo, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Equal(t, "Display Name", userInfo.Name)
	require.Equal(t, "Structured", userInfo.FirstName)
	require.Equal(t, "Person", userInfo.LastName)
}

func TestSplitDisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		firstName string
		lastName  string
	}{
		{name: "", firstName: "", lastName: ""},
		{name: "Alice", firstName: "Alice", lastName: ""},
		{name: "Alice Admin", firstName: "Alice", lastName: "Admin"},
		{name: "  Alice   Dex Admin  ", firstName: "Alice", lastName: "Dex Admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			firstName, lastName := splitDisplayName(tt.name)

			require.Equal(t, tt.firstName, firstName)
			require.Equal(t, tt.lastName, lastName)
		})
	}
}

func TestBaseOIDCProvider_GetUserInfoMissingIDToken(t *testing.T) {
	cfg := &config.SSOProviderConfig{
		Name:      "test-oidc",
		ClientID:  "test-client",
		IssuerURL: "https://example.com",
	}

	provider := &BaseOIDCProvider{
		config: cfg,
	}

	token := &oauth2.Token{AccessToken: "token"}

	_, err := provider.GetUserInfo(context.Background(), token)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no id_token")
}

func TestBaseOIDCProvider_UsesWellKnownURLForDiscovery(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	publicIssuerURL := "https://dex.example.com/dex"
	mock.IssuerURL = publicIssuerURL

	cfg := &config.SSOProviderConfig{
		Name:         "dex",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    publicIssuerURL,
		WellKnownURL: fmt.Sprintf("%s/.well-known/openid-configuration", mock.Server.URL),
	}
	logger := zap.NewNop().Sugar()

	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	require.Equal(t, fmt.Sprintf("%s/auth", publicIssuerURL), provider.oauth2Config.Endpoint.AuthURL)
	require.Equal(t, fmt.Sprintf("%s/token", mock.Server.URL), provider.oauth2Config.Endpoint.TokenURL)

	rawIDToken, err := mock.SignIDToken(map[string]any{"email": "dev@example.com"})
	require.NoError(t, err)

	token := (&oauth2.Token{AccessToken: "token"}).WithExtra(map[string]any{
		"id_token": rawIDToken,
	})

	userInfo, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "dev@example.com", userInfo.Email)
}

func TestBaseOIDCProvider_RejectsWellKnownURLIssuerMismatch(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://unexpected.example.com/dex",
			"jwks_uri":               "https://unexpected.example.com/dex/keys",
			"authorization_endpoint": "https://unexpected.example.com/dex/auth",
			"token_endpoint":         "https://unexpected.example.com/dex/token",
		})
		require.NoError(t, err)
	}))
	defer discoveryServer.Close()

	cfg := &config.SSOProviderConfig{
		Name:         "dex",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    "https://dex.example.com/dex",
		WellKnownURL: fmt.Sprintf("%s/.well-known/openid-configuration", discoveryServer.URL),
	}
	logger := zap.NewNop().Sugar()

	_, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", logger)
	require.Error(t, err)
	require.Contains(t, err.Error(), "configured issuer URL")
}

// pkceAuthorize builds the authorization URL for verifier and lets the mock IdP issue a code bound
// to the code_challenge it carries, as a real IdP would when the user signs in.
func pkceAuthorize(t *testing.T, mock *testutil.MockOIDCServer, provider *BaseOIDCProvider, verifier string) (*url.URL, string) {
	t.Helper()

	authURL, err := url.Parse(provider.GetAuthURL("state123", verifier))
	require.NoError(t, err)

	const code = "auth-code"
	mock.IssueCode(code, authURL.Query().Get("code_challenge"))
	return authURL, code
}

func TestBaseOIDCProvider_GetAuthURLCarriesPKCEChallenge(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	cfg := &config.SSOProviderConfig{
		Name:         "test-oidc",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    mock.IssuerURL,
	}
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)
	require.True(t, provider.UsesPKCE())

	verifier := oauth2.GenerateVerifier()
	authURL, _ := pkceAuthorize(t, mock, provider, verifier)

	query := authURL.Query()
	require.Equal(t, "state123", query.Get("state"))
	require.Equal(t, oauth2.S256ChallengeFromVerifier(verifier), query.Get("code_challenge"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotContains(t, authURL.String(), verifier)
}

func TestBaseOIDCProvider_ExchangeCodeSendsPKCEVerifier(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	cfg := &config.SSOProviderConfig{
		Name:         "test-oidc",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    mock.IssuerURL,
	}
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)

	verifier := oauth2.GenerateVerifier()
	_, code := pkceAuthorize(t, mock, provider, verifier)

	token, err := provider.ExchangeCode(context.Background(), code, verifier)
	require.NoError(t, err)
	require.Equal(t, "access-token", token.AccessToken)

	requests := mock.TokenRequests()
	require.Len(t, requests, 1)
	require.Equal(t, verifier, requests[0].Form.Get("code_verifier"))

	// The confidential client still authenticates with its secret.
	clientID, clientSecret, ok := basicAuth(requests[0].Header)
	require.True(t, ok)
	require.Equal(t, "test-client", clientID)
	require.Equal(t, "test-secret", clientSecret)

	userInfo, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "test-subject", userInfo.Subject)
}

func TestBaseOIDCProvider_ExchangeCodeRejectsWrongPKCEVerifier(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	cfg := &config.SSOProviderConfig{
		Name:         "test-oidc",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    mock.IssuerURL,
	}
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)

	_, code := pkceAuthorize(t, mock, provider, oauth2.GenerateVerifier())

	_, err = provider.ExchangeCode(context.Background(), code, oauth2.GenerateVerifier())
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid_grant")
}

func TestBaseOIDCProvider_ExchangeCodeRequiresPKCEVerifier(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	cfg := &config.SSOProviderConfig{
		Name:         "test-oidc",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		IssuerURL:    mock.IssuerURL,
	}
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)

	_, err = provider.ExchangeCode(context.Background(), "auth-code", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing PKCE code verifier")
	require.Empty(t, mock.TokenRequests(), "no exchange without PKCE may reach the IdP")
}

func TestBaseOIDCProvider_PublicClientExchangeSendsClientIDWithoutSecret(t *testing.T) {
	mock := testutil.NewMockOIDCServer(t)
	defer mock.Close()

	cfg := &config.SSOProviderConfig{
		Name:         "dex",
		ClientID:     "test-client",
		PublicClient: true,
		IssuerURL:    mock.IssuerURL,
	}
	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback", zap.NewNop().Sugar())
	require.NoError(t, err)

	verifier := oauth2.GenerateVerifier()
	_, code := pkceAuthorize(t, mock, provider, verifier)

	token, err := provider.ExchangeCode(context.Background(), code, verifier)
	require.NoError(t, err)

	requests := mock.TokenRequests()
	require.Len(t, requests, 1)
	form := requests[0].Form
	require.Equal(t, "test-client", form.Get("client_id"))
	require.Equal(t, verifier, form.Get("code_verifier"))
	_, hasSecret := form["client_secret"]
	require.False(t, hasSecret, "a public client must not send client_secret")
	require.Empty(t, requests[0].Header.Get("Authorization"), "a public client must not use client authentication")

	userInfo, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, "test-subject", userInfo.Subject)
}

func basicAuth(header http.Header) (string, string, bool) {
	req := &http.Request{Header: header}
	return req.BasicAuth()
}
