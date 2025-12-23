package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGitHubOAuthProvider_GetUserInfo_AppendsOrgAndTeamGroups(t *testing.T) {
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":    1234,
			"name":  "Octo Cat",
			"email": "octo@example.com",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer userInfoServer.Close()

	orgsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		resp := []map[string]any{
			{"login": "octo-org"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer orgsServer.Close()

	teamsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := []map[string]any{
			{
				"name": "Platform",
				"slug": "platform",
				"organization": map[string]any{
					"login": "octo-org",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer teamsServer.Close()

	prevOrgEndpoint := githubOrganizationsEndpoint
	prevTeamEndpoint := githubTeamsEndpoint
	githubOrganizationsEndpoint = orgsServer.URL
	githubTeamsEndpoint = teamsServer.URL
	t.Cleanup(func() {
		githubOrganizationsEndpoint = prevOrgEndpoint
		githubTeamsEndpoint = prevTeamEndpoint
	})

	cfg := &config.SSOProviderConfig{
		Name:        "github",
		ClientID:    "client",
		UserInfoURL: userInfoServer.URL,
		TokenURL:    userInfoServer.URL + "/token",
		GroupMapping: map[string][]string{
			"github-organization:octo-org":  {"ccf-octo"},
			"github-team:octo-org/platform": {"ccf-platform"},
		},
	}

	logger := zap.NewNop().Sugar()
	provider, err := NewGitHubOAuthProvider(cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := &oauth2.Token{AccessToken: "token"}
	info, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)

	require.Equal(t, "1234", info.Subject)
	require.Contains(t, info.Groups, "ccf-octo")
	require.Contains(t, info.Groups, "ccf-platform")
}

func TestGitHubOAuthProvider_GetUserInfo_TeamEndpointFailure(t *testing.T) {
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":    1234,
			"name":  "Octo Cat",
			"email": "octo@example.com",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer userInfoServer.Close()

	orgsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := []map[string]any{
			{"login": "octo-org"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer orgsServer.Close()

	teamsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer teamsServer.Close()

	prevOrgEndpoint := githubOrganizationsEndpoint
	prevTeamEndpoint := githubTeamsEndpoint
	githubOrganizationsEndpoint = orgsServer.URL
	githubTeamsEndpoint = teamsServer.URL
	t.Cleanup(func() {
		githubOrganizationsEndpoint = prevOrgEndpoint
		githubTeamsEndpoint = prevTeamEndpoint
	})

	cfg := &config.SSOProviderConfig{
		Name:        "github",
		ClientID:    "client",
		UserInfoURL: userInfoServer.URL,
		GroupMapping: map[string][]string{
			"github-organization:octo-org": {"ccf-octo"},
		},
	}

	logger := zap.NewNop().Sugar()
	provider, err := NewGitHubOAuthProvider(cfg, "https://app.example.com/callback", logger)
	require.NoError(t, err)

	token := &oauth2.Token{AccessToken: "token"}
	info, err := provider.GetUserInfo(context.Background(), token)
	require.NoError(t, err)
	require.Contains(t, info.Groups, "ccf-octo")
}
