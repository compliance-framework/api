package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type mockSSOService struct {
	enabled          bool
	state            string
	stateErr         error
	authURL          string
	authURLErr       error
	token            *oauth2.Token
	tokenErr         error
	userInfo         *types.UserInfo
	userInfoErr      error
	oauthConfigs     map[string]*oauth2.Config
	providerConfigs  map[string]*config.SSOProviderConfig
	canCreate        bool
	mappedAttributes []string
	enabledProviders []config.SSOProviderConfig
}

func newMockSSOService() *mockSSOService {
	return &mockSSOService{
		oauthConfigs:    map[string]*oauth2.Config{},
		providerConfigs: map[string]*config.SSOProviderConfig{},
	}
}

func (m *mockSSOService) IsEnabled() bool {
	return m.enabled
}

func (m *mockSSOService) GetOAuth2Config(providerName string) (*oauth2.Config, bool) {
	cfg, ok := m.oauthConfigs[providerName]
	return cfg, ok
}

func (m *mockSSOService) GetEnabledProviders() []config.SSOProviderConfig {
	return m.enabledProviders
}

func (m *mockSSOService) GenerateState() (string, error) {
	return m.state, m.stateErr
}

func (m *mockSSOService) GetAuthURL(providerName string, state string) (string, error) {
	return m.authURL, m.authURLErr
}

func (m *mockSSOService) ExchangeCode(ctx context.Context, providerName string, code string) (*oauth2.Token, error) {
	return m.token, m.tokenErr
}

func (m *mockSSOService) GetUserInfo(ctx context.Context, providerName string, token *oauth2.Token) (*types.UserInfo, error) {
	return m.userInfo, m.userInfoErr
}

func (m *mockSSOService) GetProviderConfig(providerName string) *config.SSOProviderConfig {
	return m.providerConfigs[providerName]
}

func (m *mockSSOService) CanCreateUser(userInfo *types.UserInfo, providerConfig *config.SSOProviderConfig) bool {
	return m.canCreate
}

func (m *mockSSOService) MapUserAttributes(userInfo *types.UserInfo, providerConfig *config.SSOProviderConfig) []string {
	return m.mappedAttributes
}

func setupTestHandler(t *testing.T) (*SSOHandler, *mockSSOService, *gorm.DB) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&relational.User{}, &relational.SSOUserLink{}))

	mockSvc := newMockSSOService()
	logger := zap.NewNop().Sugar()
	metrics := api.NewMetricsHandler(context.Background(), logger)

	priv, pub, err := config.GenerateKeyPair(2048)
	require.NoError(t, err)

	cfg := &config.Config{
		Environment:   "production",
		JWTPrivateKey: priv,
		JWTPublicKey:  pub,
		SSO: &config.SSOConfig{
			BaseURL: "https://app.example.com",
		},
	}

	handler := &SSOHandler{
		sugar:      logger,
		db:         db,
		config:     cfg,
		ssoService: mockSvc,
		metrics:    metrics,
	}

	return handler, mockSvc, db
}

func TestSSOHandlerInitiateLogin_SetsStateCookie(t *testing.T) {
	h, mockSvc, _ := setupTestHandler(t)
	mockSvc.enabled = true
	mockSvc.state = "state123"
	mockSvc.authURL = "https://sso.example.com/auth"
	mockSvc.oauthConfigs["google"] = &oauth2.Config{}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/google", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("provider")
	ctx.SetParamValues("google")

	err := h.InitiateLogin(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	require.Equal(t, mockSvc.authURL, rec.Header().Get("Location"))

	cookies := rec.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "oauth_state" {
			stateCookie = c
			break
		}
	}
	require.NotNil(t, stateCookie)
	require.Equal(t, "state123", stateCookie.Value)
	require.True(t, stateCookie.Secure)
	require.Equal(t, http.SameSiteStrictMode, stateCookie.SameSite)
}

func TestSSOHandlerCallback_NewUserCreated(t *testing.T) {
	h, mockSvc, db := setupTestHandler(t)
	mockSvc.enabled = true
	mockSvc.oauthConfigs["google"] = &oauth2.Config{}
	mockSvc.state = "state123"
	mockSvc.authURL = "https://sso.example.com/auth"
	mockSvc.token = &oauth2.Token{AccessToken: "token"}
	mockSvc.userInfo = &types.UserInfo{
		Subject:   "google-123",
		Email:     "new@example.com",
		FirstName: "New",
		LastName:  "User",
		Groups:    []string{"ccf-authorized"},
	}
	mockSvc.canCreate = true
	mockSvc.providerConfigs["google"] = &config.SSOProviderConfig{}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback/google", nil)
	q := req.URL.Query()
	q.Set("state", "state123")
	q.Set("code", "abc123")
	req.URL.RawQuery = q.Encode()
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "state123"})

	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("provider")
	ctx.SetParamValues("google")

	err := h.Callback(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusTemporaryRedirect, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/auth/sso/callback")

	var user relational.User
	require.NoError(t, db.Where("email = ?", "new@example.com").First(&user).Error)
	require.Equal(t, "sso", user.AuthMethod)

	var link relational.SSOUserLink
	require.NoError(t, db.Where("provider = ? AND external_id = ?", "google", "google-123").First(&link).Error)

	authCookieFound := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "ccf_auth_token" {
			authCookieFound = true
			require.NotEmpty(t, c.Value)
			require.True(t, c.Secure)
			break
		}
	}
	require.True(t, authCookieFound, "expected auth cookie to be set")
}

func TestSSOHandler_findByExistingLink_ReturnsUser(t *testing.T) {
	h, mockSvc, db := setupTestHandler(t)
	mockSvc.providerConfigs["google"] = &config.SSOProviderConfig{}
	mockSvc.mappedAttributes = []string{"ccf-admins"}

	user := &relational.User{
		Email:      "existing@example.com",
		AuthMethod: "sso",
	}
	require.NoError(t, db.Create(user).Error)

	link := &relational.SSOUserLink{
		UserID:     user.ID.String(),
		Provider:   "google",
		ExternalID: "sub-123",
		Email:      "existing@example.com",
		Groups:     sso.SerializeStringArray([]string{"group1"}),
		LastSync:   time.Now().Add(-time.Hour),
	}
	require.NoError(t, db.Create(link).Error)

	info := &types.UserInfo{
		Subject: "sub-123",
		Groups:  []string{"group1"},
	}

	found, err := h.findByExistingLink("google", info)
	require.NoError(t, err)
	require.Equal(t, user.ID, found.ID)

	var updatedLink relational.SSOUserLink
	require.NoError(t, db.First(&updatedLink, "id = ?", link.ID).Error)
	require.WithinDuration(t, time.Now(), updatedLink.LastSync, time.Second)
	require.Equal(t, sso.SerializeStringArray(info.Groups), updatedLink.Groups)
}

func TestSSOHandler_linkExistingUser_CreatesLink(t *testing.T) {
	h, _, db := setupTestHandler(t)

	user := &relational.User{
		Email: "existing@example.com",
	}
	require.NoError(t, db.Create(user).Error)

	info := &types.UserInfo{
		Subject: "sub-999",
		Email:   "existing@example.com",
		Groups:  []string{"group-x"},
	}

	found, err := h.linkExistingUser("google", info)
	require.NoError(t, err)
	require.Equal(t, user.ID, found.ID)

	var link relational.SSOUserLink
	require.NoError(t, db.Where("provider = ? AND external_id = ?", "google", "sub-999").First(&link).Error)
	require.Equal(t, user.ID.String(), link.UserID)
	require.Equal(t, sso.SerializeStringArray(info.Groups), link.Groups)
}

func uuidPtr(t *testing.T) *uuid.UUID {
	t.Helper()
	id := uuid.New()
	return &id
}
