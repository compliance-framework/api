package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/providers/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGoogleOIDCProvider_GetUserInfo_AppendsGoogleGroups(t *testing.T) {
	mockOIDC := testutil.NewMockOIDCServer(t)
	defer mockOIDC.Close()

	claims := map[string]any{
		"email":       "user@example.com",
		"name":        "Example User",
		"given_name":  "Example",
		"family_name": "User",
	}
	rawIDToken, err := mockOIDC.SignIDToken(claims)
	require.NoError(t, err)

	groupsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		resp := map[string]any{
			"groups": []map[string]any{
				{"email": "engineering@example.com"},
				{"email": "sales@example.com"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer groupsServer.Close()

	prevEndpoint := googleGroupsEndpoint
	googleGroupsEndpoint = groupsServer.URL
	t.Cleanup(func() {
		googleGroupsEndpoint = prevEndpoint
	})

	cfg := &config.SSOProviderConfig{
		Name:      "google",
		ClientID:  "test-client",
		IssuerURL: mockOIDC.IssuerURL,
		GroupMapping: map[string][]string{
			"google-group:engineering@example.com": {"ccf-engineering"},
			"google-group:sales@example.com":       {"ccf-sales"},
		},
	}

	provider, err := NewGoogleOIDCProvider(context.Background(), cfg, "https://app.example.com/callback")
	require.NoError(t, err)

	token := (&oauth2.Token{AccessToken: "token"}).WithExtra(map[string]any{
		"id_token": rawIDToken,
	})

	info, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Contains(t, info.Groups, "ccf-engineering")
	require.Contains(t, info.Groups, "ccf-sales")
}

func TestGoogleOIDCProvider_GetUserInfo_GroupRequestFailure(t *testing.T) {
	mockOIDC := testutil.NewMockOIDCServer(t)
	defer mockOIDC.Close()

	rawIDToken, err := mockOIDC.SignIDToken(nil)
	require.NoError(t, err)

	groupsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer groupsServer.Close()

	prevEndpoint := googleGroupsEndpoint
	googleGroupsEndpoint = groupsServer.URL
	t.Cleanup(func() { googleGroupsEndpoint = prevEndpoint })

	cfg := &config.SSOProviderConfig{
		Name:      "google",
		ClientID:  "test-client",
		IssuerURL: mockOIDC.IssuerURL,
	}

	provider, err := NewGoogleOIDCProvider(context.Background(), cfg, "https://app.example.com/callback")
	require.NoError(t, err)

	token := (&oauth2.Token{AccessToken: "token"}).WithExtra(map[string]any{
		"id_token": rawIDToken,
	})

	info, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)
	require.Empty(t, info.Groups)
}
