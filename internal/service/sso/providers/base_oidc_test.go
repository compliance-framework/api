package providers

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/providers/testutil"
	"github.com/stretchr/testify/require"
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

	provider, err := NewBaseOIDCProvider(context.Background(), cfg, "https://app.example.com/callback")
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
