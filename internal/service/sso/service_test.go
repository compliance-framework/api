package sso

import (
	"context"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type mockProvider struct {
	name      string
	protocol  string
	cfg       *config.SSOProviderConfig
	authURL   string
	token     *oauth2.Token
	userInfo  *types.UserInfo
	tokenErr  error
	userErr   error
	exchanged bool
}

func (m *mockProvider) GetAuthURL(state string) string {
	return m.authURL + "?state=" + state
}

func (m *mockProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	m.exchanged = true
	if m.token != nil {
		return m.token, m.tokenErr
	}
	return &oauth2.Token{AccessToken: "token-" + code}, m.tokenErr
}

func (m *mockProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error) {
	return m.userInfo, m.userErr
}

func (m *mockProvider) GetProviderConfig() *config.SSOProviderConfig {
	return m.cfg
}

func (m *mockProvider) GetName() string {
	return m.name
}

func (m *mockProvider) GetProtocol() string {
	return m.protocol
}

func TestNewService_InitializesProviders(t *testing.T) {
	defer restoreProviderFactory()

	createdProviders := map[string]*mockProvider{}
	providerFactory = func(cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (Provider, error) {
		mp := &mockProvider{
			name:     cfg.Name,
			protocol: cfg.Protocol,
			cfg:      cfg,
			authURL:  "https://auth/" + cfg.Name,
			userInfo: &types.UserInfo{Subject: cfg.Name},
		}
		createdProviders[cfg.Name] = mp
		return mp, nil
	}

	cfg := &config.SSOConfig{
		Enabled:     true,
		CallbackURL: "https://app/callback",
		Providers: []config.SSOProviderConfig{
			{Name: "google", Protocol: "oidc", Enabled: true},
			{Name: "github", Protocol: "oauth", Enabled: true},
		},
	}

	logger := zap.NewNop().Sugar()
	service, err := NewService(cfg, logger)
	require.NoError(t, err)

	require.Equal(t, 2, len(service.providers))
	require.NotNil(t, service.providers["google"])
	require.NotNil(t, service.providers["github"])
}

func TestService_MethodsUseRegisteredProvider(t *testing.T) {
	defer restoreProviderFactory()

	mp := &mockProvider{
		name:     "google",
		protocol: "oidc",
		cfg:      &config.SSOProviderConfig{Name: "google"},
		authURL:  "https://auth/google",
		token:    &oauth2.Token{AccessToken: "token123"},
		userInfo: &types.UserInfo{Subject: "sub"},
	}

	providerFactory = func(cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (Provider, error) {
		return mp, nil
	}

	cfg := &config.SSOConfig{
		Enabled:     true,
		CallbackURL: "https://app/callback",
		Providers: []config.SSOProviderConfig{
			{Name: "google", Protocol: "oidc", Enabled: true},
		},
	}
	service, err := NewService(cfg, zap.NewNop().Sugar())
	require.NoError(t, err)

	url, err := service.GetAuthURL("google", "state123")
	require.NoError(t, err)
	require.True(t, strings.Contains(url, "state123"))

	token, err := service.ExchangeCode(context.Background(), "google", "code123")
	require.NoError(t, err)
	require.Equal(t, "token123", token.AccessToken)
	require.True(t, mp.exchanged)

	info, err := service.GetUserInfo(context.Background(), "google", token)
	require.NoError(t, err)
	require.Equal(t, "sub", info.Subject)

	cfgReturned := service.GetProviderConfig("google")
	require.Equal(t, "google", cfgReturned.Name)

	placeholder, ok := service.GetOAuth2Config("google")
	require.True(t, ok)
	require.NotNil(t, placeholder)

	_, err = service.GetAuthURL("unknown", "state")
	require.Error(t, err)
}

func TestService_GenerateStateToken(t *testing.T) {
	service := &Service{}
	state, err := service.GenerateStateToken()
	require.NoError(t, err)
	require.NotEmpty(t, state)

	state2, err := service.GenerateState()
	require.NoError(t, err)
	require.NotEmpty(t, state2)
	require.NotEqual(t, state, state2)
}

func TestService_CanCreateUser(t *testing.T) {
	service := &Service{}
	providerCfg := &config.SSOProviderConfig{
		RequiredLoginGroups: []string{"CCF-admins"},
	}

	user := &types.UserInfo{
		Groups: []string{"ccf-admins", "engineering"},
	}

	require.True(t, service.CanCreateUser(user, providerCfg))

	user.Groups = []string{"engineering"}
	require.False(t, service.CanCreateUser(user, providerCfg))

	// No required groups = always true
	require.True(t, service.CanCreateUser(user, &config.SSOProviderConfig{}))
}

func TestService_MapUserAttributes(t *testing.T) {
	service := &Service{}
	user := &types.UserInfo{Groups: []string{"a", "b"}}

	require.Nil(t, service.MapUserAttributes(user, nil))

	cfg := &config.SSOProviderConfig{GroupMapping: map[string][]string{"key": {"value"}}}
	require.Equal(t, []string{"a", "b"}, service.MapUserAttributes(user, cfg))
}

func restoreProviderFactory() {
	providerFactory = CreateProvider
}
