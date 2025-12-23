package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/sso"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

type ssoService interface {
	IsEnabled() bool
	GetOAuth2Config(providerName string) (*oauth2.Config, bool)
	GetEnabledProviders() []config.SSOProviderConfig
	GenerateState() (string, error)
	GetAuthURL(providerName string, state string) (string, error)
	ExchangeCode(ctx context.Context, providerName string, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, providerName string, token *oauth2.Token) (*types.UserInfo, error)
	GetProviderConfig(providerName string) *config.SSOProviderConfig
	CanCreateUser(userInfo *types.UserInfo, providerConfig *config.SSOProviderConfig) bool
	MapUserAttributes(userInfo *types.UserInfo, providerConfig *config.SSOProviderConfig) []string
}

type SSOHandler struct {
	sugar      *zap.SugaredLogger
	db         *gorm.DB
	config     *config.Config
	ssoService ssoService
	metrics    *api.PrometheusMetrics
}

func NewSSOHandler(
	logger *zap.SugaredLogger,
	db *gorm.DB,
	cfg *config.Config,
	ssoSvc *sso.Service,
	metrics *api.PrometheusMetrics,
) *SSOHandler {
	if err := db.AutoMigrate(&relational.User{}, &relational.SSOUserLink{}); err != nil {
		logger.Warnw("Failed to auto-migrate SSO-related tables", "error", err)
	}

	return &SSOHandler{
		sugar:      logger,
		db:         db,
		config:     cfg,
		ssoService: ssoSvc,
		metrics:    metrics,
	}
}

func (h *SSOHandler) Register(api *echo.Group) {
	api.GET("/sso/providers", h.ListProviders)
	api.GET("/sso/:provider", h.InitiateLogin)
	api.GET("/sso/callback/:provider", h.Callback)
}

type ProviderInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Enabled     bool   `json:"enabled"`
	IconURL     string `json:"iconUrl,omitempty"`
}

func (h *SSOHandler) ListProviders(ctx echo.Context) error {
	if !h.ssoService.IsEnabled() {
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]ProviderInfo]{
			Data: []ProviderInfo{},
		})
	}

	providers := h.ssoService.GetEnabledProviders()
	result := make([]ProviderInfo, 0, len(providers))
	for _, p := range providers {
		result = append(result, ProviderInfo{
			Name:        p.Name,
			DisplayName: p.DisplayName,
			Enabled:     p.Enabled,
			IconURL:     p.IconURL,
		})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[[]ProviderInfo]{
		Data: result,
	})
}

func (h *SSOHandler) InitiateLogin(ctx echo.Context) error {
	providerName := ctx.Param("provider")

	if !h.ssoService.IsEnabled() {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSO is not enabled")))
	}

	_, exists := h.ssoService.GetOAuth2Config(providerName)
	if !exists {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("provider %s not found", providerName)))
	}

	state, err := h.ssoService.GenerateState()
	if err != nil {
		h.sugar.Errorw("Failed to generate state", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	cookie := new(http.Cookie)
	cookie.Name = "oauth_state"
	cookie.Value = state
	cookie.Expires = time.Now().Add(5 * time.Minute)
	cookie.HttpOnly = true
	cookie.Path = "/"

	if isDevelopmentEnvironment(h.config.Environment) {
		cookie.Secure = false
		cookie.SameSite = http.SameSiteLaxMode
	} else {
		cookie.Secure = true
		cookie.SameSite = http.SameSiteStrictMode
	}

	ctx.SetCookie(cookie)

	authURL, err := h.ssoService.GetAuthURL(providerName, state)
	if err != nil {
		h.sugar.Errorw("Failed to get auth URL", "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.Redirect(http.StatusTemporaryRedirect, authURL)
}

func (h *SSOHandler) Callback(ctx echo.Context) error {
	providerName := ctx.Param("provider")

	if !h.ssoService.IsEnabled() {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("SSO is not enabled")))
	}

	storedState, err := ctx.Cookie("oauth_state")
	if err != nil {
		h.sugar.Warnw("State cookie not found", "error", err)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=invalid_state")
	}

	receivedState := ctx.QueryParam("state")
	if storedState.Value != receivedState {
		h.sugar.Warnw("State mismatch", "stored", storedState.Value, "received", receivedState)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=invalid_state")
	}

	clearCookie := new(http.Cookie)
	clearCookie.Name = "oauth_state"
	clearCookie.Value = ""
	clearCookie.Expires = time.Now().Add(-1 * time.Hour)
	clearCookie.HttpOnly = true
	clearCookie.Path = "/"
	ctx.SetCookie(clearCookie)

	if errParam := ctx.QueryParam("error"); errParam != "" {
		errDesc := ctx.QueryParam("error_description")
		h.sugar.Warnw("OAuth error from provider", "error", errParam, "description", errDesc)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error="+errParam)
	}

	code := ctx.QueryParam("code")
	if code == "" {
		h.sugar.Warn("No authorization code in callback")
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=no_code")
	}

	token, err := h.ssoService.ExchangeCode(ctx.Request().Context(), providerName, code)
	if err != nil {
		h.sugar.Errorw("Failed to exchange code for token", "provider", providerName, "error", err)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=token_exchange_failed")
	}

	userInfo, err := h.ssoService.GetUserInfo(ctx.Request().Context(), providerName, token)
	if err != nil {
		h.sugar.Errorw("Failed to get user info", "provider", providerName, "error", err)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=user_info_failed")
	}

	if err := h.enforceRequiredLoginGroups(providerName, userInfo.Groups); err != nil {
		h.sugar.Warnw("User missing required login groups", "provider", providerName, "error", err, "groups", userInfo.Groups)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=missing_group")
	}

	user, err := h.findOrCreateUser(providerName, userInfo)
	if err != nil {
		h.sugar.Errorw("Failed to find or create user", "provider", providerName, "error", err)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=user_creation_failed")
	}

	jwtToken, err := authn.GenerateJWTToken(user, h.config.JWTPrivateKey)
	if err != nil {
		h.sugar.Errorw("Failed to generate JWT token", "error", err)
		return ctx.Redirect(http.StatusTemporaryRedirect, h.config.SSO.BaseURL+"/login?error=token_generation_failed")
	}

	authCookie := new(http.Cookie)
	authCookie.Name = "ccf_auth_token"
	authCookie.Value = *jwtToken
	authCookie.Expires = time.Now().Add(time.Hour * 24)
	authCookie.HttpOnly = true
	authCookie.Path = "/"

	if isDevelopmentEnvironment(h.config.Environment) {
		authCookie.Secure = false
		authCookie.SameSite = http.SameSiteLaxMode
	} else {
		authCookie.Secure = true
		authCookie.SameSite = http.SameSiteStrictMode
	}

	ctx.SetCookie(authCookie)

	h.metrics.Counters.TotalLogins.Inc()

	baseURL := strings.TrimRight(h.config.SSO.BaseURL, "/")
	redirectURL := fmt.Sprintf("%s/auth/sso/callback?provider=%s", baseURL, url.QueryEscape(providerName))

	return ctx.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

func (h *SSOHandler) findOrCreateUser(providerName string, userInfo *types.UserInfo) (*relational.User, error) {
	if user, err := h.findByExistingLink(providerName, userInfo); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	} else if user != nil {
		return user, nil
	}

	if user, err := h.linkExistingUser(providerName, userInfo); err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	} else if user != nil {
		return user, nil
	}

	return h.createUserAndLink(providerName, userInfo)
}

func (h *SSOHandler) findByExistingLink(providerName string, userInfo *types.UserInfo) (*relational.User, error) {
	var ssoLink relational.SSOUserLink
	err := h.db.Where("provider = ? AND external_id = ?", providerName, userInfo.Subject).
		Preload("User").First(&ssoLink).Error

	if err != nil {
		return nil, err
	}

	if ssoLink.User.DeletedAt.Valid {
		if delErr := h.db.Unscoped().Delete(&ssoLink).Error; delErr != nil {
			return nil, fmt.Errorf("failed to remove stale SSO link: %w", delErr)
		}
		return nil, gorm.ErrRecordNotFound
	}

	now := time.Now()
	h.db.Model(&ssoLink).Update("last_sync", now)

	providerConfig := h.ssoService.GetProviderConfig(providerName)
	if providerConfig != nil {
		userAttributes := h.ssoService.MapUserAttributes(userInfo, providerConfig)
		if len(userAttributes) > 0 {
			h.db.Model(&ssoLink.User).Update("user_attributes", sso.SerializeStringArray(userAttributes))
		}
		h.db.Model(&ssoLink).Update("groups", sso.SerializeStringArray(userInfo.Groups))
	}

	h.updateLastLogin(&ssoLink.User, now)

	return &ssoLink.User, nil
}

func (h *SSOHandler) linkExistingUser(providerName string, userInfo *types.UserInfo) (*relational.User, error) {
	var existingUser relational.User
	err := h.db.Where("email = ?", userInfo.Email).First(&existingUser).Error
	if err != nil {
		return nil, err
	}

	now := time.Now()
	link := relational.SSOUserLink{
		UserID:     existingUser.ID.String(),
		Provider:   providerName,
		ExternalID: userInfo.Subject,
		Email:      userInfo.Email,
		Groups:     sso.SerializeStringArray(userInfo.Groups),
		LastSync:   now,
	}

	if err := h.db.Create(&link).Error; err != nil {
		return nil, fmt.Errorf("failed to create SSO link: %w", err)
	}

	h.db.Model(&existingUser).Updates(map[string]interface{}{
		"auth_method": "sso",
	})
	h.updateLastLogin(&existingUser, now)

	return &existingUser, nil
}

func (h *SSOHandler) createUserAndLink(providerName string, userInfo *types.UserInfo) (*relational.User, error) {
	providerConfig := h.ssoService.GetProviderConfig(providerName)
	if !h.ssoService.CanCreateUser(userInfo, providerConfig) {
		return nil, fmt.Errorf("user not authorized for JIT registration: no matching group found")
	}

	userAttributes := h.ssoService.MapUserAttributes(userInfo, providerConfig)
	now := time.Now()

	user := &relational.User{
		Email:      userInfo.Email,
		FirstName:  userInfo.FirstName,
		LastName:   userInfo.LastName,
		AuthMethod: "sso",
		IsActive:   true,
		LastLogin:  &now,
	}

	if err := h.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	h.db.Model(&user).Update("user_attributes", sso.SerializeStringArray(userAttributes))

	link := relational.SSOUserLink{
		UserID:     user.ID.String(),
		Provider:   providerName,
		ExternalID: userInfo.Subject,
		Email:      userInfo.Email,
		Groups:     sso.SerializeStringArray(userInfo.Groups),
		LastSync:   now,
	}

	if err := h.db.Create(&link).Error; err != nil {
		return nil, fmt.Errorf("failed to create SSO link: %w", err)
	}

	h.sugar.Infow("Created new user via SSO JIT registration",
		"email", user.Email,
		"provider", providerName,
		"attributes", userAttributes,
	)

	return user, nil
}

func (h *SSOHandler) updateLastLogin(user *relational.User, when time.Time) {
	if user == nil || user.ID == nil {
		h.sugar.Warnw("Cannot update last login for user without ID")
		return
	}

	if err := h.db.Model(&relational.User{}).
		Where("id = ?", user.ID.String()).
		Update("last_login", when).Error; err != nil {
		h.sugar.Errorw("Failed to update last login", "userID", user.ID.String(), "error", err)
		return
	}

	user.LastLogin = &when
}

func (h *SSOHandler) enforceRequiredLoginGroups(providerName string, userGroups []string) error {
	providerConfig := h.ssoService.GetProviderConfig(providerName)
	if providerConfig == nil || len(providerConfig.RequiredLoginGroups) == 0 {
		return nil
	}

	groupSet := make(map[string]struct{}, len(userGroups))
	for _, g := range userGroups {
		normalized := strings.TrimSpace(strings.ToLower(g))
		if normalized != "" {
			groupSet[normalized] = struct{}{}
		}
	}

	var missing []string
	for _, required := range providerConfig.RequiredLoginGroups {
		normalized := strings.TrimSpace(strings.ToLower(required))
		if _, ok := groupSet[normalized]; !ok {
			missing = append(missing, required)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required login groups: %s", strings.Join(missing, ", "))
	}

	return nil
}
