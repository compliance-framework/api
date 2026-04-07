package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/api"
	"github.com/compliance-framework/api/internal/api/handler"
	"github.com/compliance-framework/api/internal/authn"
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	slackLinkStateCookieName = "slack_link_state"
	slackLinkCookieTTL       = 10 * time.Minute
)

const (
	slackBaseURL            = "https://slack.com"
	slackOpenIDUserInfoURL  = slackBaseURL + "/api/openid.connect.userInfo"
	slackOpenIDAuthorizeURL = slackBaseURL + "/openid/connect/authorize"
	slackOpenIDTokenURL     = slackBaseURL + "/api/openid.connect.token"
)

var errInvalidOrExpiredSlackLinkState = errors.New("invalid or expired Slack link state")

type SlackLinkHandler struct {
	sugar       *zap.SugaredLogger
	db          *gorm.DB
	config      *config.Config
	oauthConfig *oauth2.Config
	httpClient  *http.Client
}

type slackOpenIDUserInfo struct {
	OK bool `json:"ok"`

	Subject string `json:"sub"`
	UserID  string `json:"https://slack.com/user_id"`
	TeamID  string `json:"https://slack.com/team_id"`

	TeamName   string `json:"https://slack.com/team_name"`
	TeamDomain string `json:"https://slack.com/team_domain"`

	Name  string `json:"name"`
	Email string `json:"email"`

	Error string `json:"error"`
}

type slackLinkStatusResponse struct {
	Linked           bool      `json:"linked"`
	SlackUserID      string    `json:"slackUserId,omitempty"`
	SlackTeamID      string    `json:"slackTeamId,omitempty"`
	SlackTeamDomain  string    `json:"slackTeamDomain,omitempty"`
	SlackTeamName    string    `json:"slackTeamName,omitempty"`
	SlackDisplayName string    `json:"slackDisplayName,omitempty"`
	SlackEmail       string    `json:"slackEmail,omitempty"`
	LinkedAt         time.Time `json:"linkedAt,omitempty"`
}

func NewSlackLinkHandler(logger *zap.SugaredLogger, db *gorm.DB, cfg *config.Config) *SlackLinkHandler {
	return &SlackLinkHandler{
		sugar:       logger,
		db:          db,
		config:      cfg,
		oauthConfig: newSlackOAuthConfig(cfg),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (h *SlackLinkHandler) Register(api *echo.Group, jwtMiddleware echo.MiddlewareFunc) {
	if api == nil || jwtMiddleware == nil {
		return
	}

	authenticated := api.Group("/slack/link")
	authenticated.Use(jwtMiddleware)
	authenticated.GET("/start", h.StartLink)
	authenticated.GET("/status", h.GetStatus)
	authenticated.DELETE("", h.Unlink)

	api.GET("/slack/link/callback", h.Callback)
}

func (h *SlackLinkHandler) StartLink(ctx echo.Context) error {

	if !h.isLinkingConfigured() {
		h.sugar.Error("Slack linking attempted but Slack integration is not configured")
		return h.respondCallbackError(ctx, "not_configured")
	}

	user, err := h.getCurrentUser(ctx)
	if err != nil {
		h.sugar.Warnf("Unauthorized attempt to start Slack linking: %v", err)
		return h.respondCallbackError(ctx, "unauthorized")
	}

	state, err := generateStateToken()
	if err != nil {
		h.sugar.Errorw("failed to generate Slack link state token", "error", err)
		return h.respondCallbackError(ctx, "init_failed")
	}

	expiresAt := time.Now().UTC().Add(slackLinkCookieTTL)
	if err := h.createLinkAttempt(ctx.Request().Context(), user.ID.String(), state, expiresAt); err != nil {
		h.sugar.Errorw("failed to persist Slack link state", "userID", user.ID.String(), "error", err)
		return h.respondCallbackError(ctx, "init_failed")
	}

	h.setLinkCookie(ctx, slackLinkStateCookieName, state, slackLinkCookieTTL)

	authURL := h.oauthConfig.AuthCodeURL(state)
	return ctx.Redirect(http.StatusTemporaryRedirect, authURL)
}

func (h *SlackLinkHandler) Callback(ctx echo.Context) error {
	if !h.isLinkingConfigured() {
		return h.respondCallbackError(ctx, "not_configured")
	}

	defer h.clearLinkCookie(ctx, slackLinkStateCookieName)

	if errParam := strings.TrimSpace(ctx.QueryParam("error")); errParam != "" {
		h.sugar.Warnw("Received error from Slack OAuth callback", "error", errParam)
		return h.respondCallbackError(ctx, "unauthorized")
	}

	stateCookie, err := ctx.Cookie(slackLinkStateCookieName)
	if err != nil {
		return h.respondCallbackError(ctx, "error_occurred")
	}

	receivedState := strings.TrimSpace(ctx.QueryParam("state"))
	if receivedState == "" || stateCookie.Value != receivedState {
		return h.respondCallbackError(ctx, "error_occurred")
	}

	userID, err := h.consumeLinkAttempt(ctx.Request().Context(), receivedState)
	if err != nil {
		h.sugar.Errorw("Failed to consume Slack link attempt", "error", err)
		if errors.Is(err, errInvalidOrExpiredSlackLinkState) {
			return h.respondCallbackError(ctx, "error_occurred")
		}

		return h.respondCallbackError(ctx, "error_occurred")
	}

	code := strings.TrimSpace(ctx.QueryParam("code"))
	if code == "" {
		return h.respondCallbackError(ctx, "error_occurred")
	}

	token, err := h.oauthConfig.Exchange(ctx.Request().Context(), code)
	if err != nil {
		h.sugar.Errorw("Failed to exchange Slack authorization code", "error", err)
		return h.respondCallbackError(ctx, "error_occurred")
	}

	if strings.TrimSpace(token.AccessToken) == "" {
		return h.respondCallbackError(ctx, "error_occurred")
	}

	userInfo, err := h.fetchSlackUserInfo(ctx.Request().Context(), token.AccessToken)
	if err != nil {
		h.sugar.Errorw("Failed to fetch Slack user info", "error", err)
		return h.respondCallbackError(ctx, "error_occurred")
	}

	if strings.TrimSpace(userInfo.UserID) == "" || strings.TrimSpace(userInfo.TeamID) == "" {
		return h.respondCallbackError(ctx, "error_occurred")
	}

	_, err = h.upsertSlackLink(ctx.Request().Context(), userID, userInfo)
	if err != nil {
		h.sugar.Errorw("Failed to persist Slack user link", "error", err)
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return h.respondCallbackError(ctx, "linking_exists")
		}

		return h.respondCallbackError(ctx, "error_occurred")
	}
	return h.respondCallbackSuccess(ctx)
}

func (h *SlackLinkHandler) GetStatus(ctx echo.Context) error {
	if !h.isLinkingConfigured() {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("slack account linking is not configured")))
	}

	user, err := h.getCurrentUser(ctx)
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(err))
	}

	var link relational.SlackUserLink
	tx := h.db.Where("user_id = ?", user.ID.String()).Limit(1).Find(&link)
	if tx.Error != nil {
		h.sugar.Errorw("Failed to fetch Slack link status", "userID", user.ID.String(), "error", tx.Error)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(tx.Error))
	}
	if tx.RowsAffected == 0 {
		return ctx.JSON(http.StatusOK, handler.GenericDataResponse[slackLinkStatusResponse]{
			Data: slackLinkStatusResponse{
				Linked: false,
			},
		})
	}

	return ctx.JSON(http.StatusOK, handler.GenericDataResponse[slackLinkStatusResponse]{
		Data: slackLinkStatusResponse{
			Linked:           true,
			SlackUserID:      link.SlackUserID,
			SlackTeamID:      link.SlackTeamID,
			SlackTeamDomain:  link.SlackTeamDomain,
			SlackTeamName:    link.SlackTeamName,
			SlackDisplayName: link.SlackDisplayName,
			SlackEmail:       link.SlackEmail,
			LinkedAt:         link.LastLinkedAt,
		},
	})
}

func (h *SlackLinkHandler) Unlink(ctx echo.Context) error {
	if !h.isLinkingConfigured() {
		return ctx.JSON(http.StatusNotFound, api.NewError(fmt.Errorf("slack account linking is not configured")))
	}

	user, err := h.getCurrentUser(ctx)
	if err != nil {
		return ctx.JSON(http.StatusUnauthorized, api.NewError(err))
	}

	if err := h.db.Where("user_id = ?", user.ID.String()).Delete(&relational.SlackUserLink{}).Error; err != nil {
		h.sugar.Errorw("Failed to unlink Slack account", "userID", user.ID.String(), "error", err)
		return ctx.JSON(http.StatusInternalServerError, api.NewError(err))
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (h *SlackLinkHandler) fetchSlackUserInfo(ctx context.Context, accessToken string) (*slackOpenIDUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, slackOpenIDUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build Slack user info request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Slack user info endpoint: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			h.sugar.Warnw("Failed to close Slack user info response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Slack user info response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("slack user info request failed with status %d", resp.StatusCode)
	}

	var userInfo slackOpenIDUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode Slack user info response: %w", err)
	}

	if !userInfo.OK {
		if strings.TrimSpace(userInfo.Error) != "" {
			return nil, fmt.Errorf("slack user info request failed: %s", userInfo.Error)
		}
		return nil, fmt.Errorf("slack user info request failed")
	}

	if strings.TrimSpace(userInfo.UserID) == "" {
		userInfo.UserID = strings.TrimSpace(userInfo.Subject)
	}

	return &userInfo, nil
}

func (h *SlackLinkHandler) upsertSlackLink(ctx context.Context, userID string, userInfo *slackOpenIDUserInfo) (*relational.SlackUserLink, error) {
	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID in Slack link callback: %w", err)
	}

	var result *relational.SlackUserLink

	txErr := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user relational.User
		if err := tx.First(&user, parsedUserID).Error; err != nil {
			return fmt.Errorf("failed to load user for Slack linking: %w", err)
		}

		var existingByIdentity relational.SlackUserLink
		identityTx := tx.
			Where("slack_team_id = ? AND slack_user_id = ?", userInfo.TeamID, userInfo.UserID).
			Limit(1).
			Find(&existingByIdentity)
		if identityTx.Error != nil {
			return fmt.Errorf("failed checking existing Slack identity link: %w", identityTx.Error)
		}
		if identityTx.RowsAffected > 0 && existingByIdentity.UserID != user.ID.String() {
			return gorm.ErrDuplicatedKey
		}

		now := time.Now().UTC()
		updates := map[string]interface{}{
			"slack_user_id":      userInfo.UserID,
			"slack_team_id":      userInfo.TeamID,
			"slack_team_domain":  strings.TrimSpace(userInfo.TeamDomain),
			"slack_team_name":    strings.TrimSpace(userInfo.TeamName),
			"slack_display_name": strings.TrimSpace(userInfo.Name),
			"slack_email":        strings.TrimSpace(userInfo.Email),
			"last_linked_at":     now,
		}

		var link relational.SlackUserLink
		linkTx := tx.
			Where("user_id = ?", user.ID.String()).
			Limit(1).
			Find(&link)
		if linkTx.Error != nil {
			return fmt.Errorf("failed to load existing Slack link: %w", linkTx.Error)
		}

		if linkTx.RowsAffected == 0 {
			link = relational.SlackUserLink{
				UserID:           user.ID.String(),
				SlackUserID:      userInfo.UserID,
				SlackTeamID:      userInfo.TeamID,
				SlackTeamDomain:  strings.TrimSpace(userInfo.TeamDomain),
				SlackTeamName:    strings.TrimSpace(userInfo.TeamName),
				SlackDisplayName: strings.TrimSpace(userInfo.Name),
				SlackEmail:       strings.TrimSpace(userInfo.Email),
				LastLinkedAt:     now,
			}
			if err := tx.Create(&link).Error; err != nil {
				if errors.Is(err, gorm.ErrDuplicatedKey) {
					return gorm.ErrDuplicatedKey
				}
				return fmt.Errorf("failed to create Slack link: %w", err)
			}
		} else {
			if err := tx.Model(&link).Updates(updates).Error; err != nil {
				return fmt.Errorf("failed to update Slack link: %w", err)
			}

			if err := tx.Where("id = ?", link.ID.String()).First(&link).Error; err != nil {
				return fmt.Errorf("failed to reload Slack link: %w", err)
			}
		}

		result = &link
		return nil
	})

	if txErr != nil {
		return nil, txErr
	}

	return result, nil
}

func (h *SlackLinkHandler) createLinkAttempt(ctx context.Context, userID, state string, expiresAt time.Time) error {
	attempt := relational.SlackLinkAttempt{
		State:     state,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}
	if err := h.db.WithContext(ctx).Create(&attempt).Error; err != nil {
		return fmt.Errorf("failed to create Slack link attempt: %w", err)
	}
	h.sugar.Debugw(
		"Created Slack link attempt",
		"userID", userID,
		"statePrefix", shortStateToken(state),
		"expiresAt", expiresAt,
	)
	return nil
}

func (h *SlackLinkHandler) consumeLinkAttempt(ctx context.Context, state string) (string, error) {
	now := time.Now().UTC()
	statePrefix := shortStateToken(state)
	var userID string

	err := h.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var attempt relational.SlackLinkAttempt
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
			Where("state = ? AND expires_at > ?", state, now).
			Limit(1).
			First(&attempt).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errInvalidOrExpiredSlackLinkState
			}
			return fmt.Errorf("failed to load Slack link attempt: %w", err)
		}

		userID = strings.TrimSpace(attempt.UserID)
		if userID == "" {
			return fmt.Errorf("stored Slack link attempt is missing user ID")
		}

		if err := tx.Delete(&attempt).Error; err != nil {
			return fmt.Errorf("failed to consume Slack link attempt: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errInvalidOrExpiredSlackLinkState) {
			h.sugar.Debugw(
				"Slack link attempt not found or expired",
				"statePrefix", statePrefix,
			)
		}
		return "", err
	}

	h.sugar.Debugw(
		"Consumed Slack link attempt",
		"userID", userID,
		"statePrefix", statePrefix,
	)

	return userID, nil
}

func (h *SlackLinkHandler) getCurrentUser(ctx echo.Context) (*relational.User, error) {
	userClaims, ok := ctx.Get("user").(*authn.UserClaims)
	if !ok || userClaims == nil {
		return nil, fmt.Errorf("missing user claims")
	}

	email := strings.TrimSpace(userClaims.Subject)
	if email == "" {
		return nil, fmt.Errorf("missing user email in claims")
	}

	var user relational.User
	if err := h.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	if user.ID == nil {
		return nil, fmt.Errorf("user record is missing ID")
	}

	return &user, nil
}

func (h *SlackLinkHandler) setLinkCookie(ctx echo.Context, name, value string, ttl time.Duration) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.Value = value
	cookie.Expires = time.Now().Add(ttl)
	cookie.HttpOnly = true
	cookie.Path = "/"
	// OAuth callback is cross-site navigation from Slack -> API callback.
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Secure = true
	ctx.SetCookie(cookie)
}

func (h *SlackLinkHandler) clearLinkCookie(ctx echo.Context, name string) {
	cookie := new(http.Cookie)
	cookie.Name = name
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-1 * time.Hour)
	cookie.HttpOnly = true
	cookie.Path = "/"
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Secure = true
	ctx.SetCookie(cookie)
}

func (h *SlackLinkHandler) isLinkingConfigured() bool {
	if h == nil || h.config == nil || h.config.Slack == nil || !h.config.Slack.Enabled {
		return false
	}
	if h.oauthConfig == nil {
		return false
	}
	return true
}

func newSlackOAuthConfig(cfg *config.Config) *oauth2.Config {
	if cfg == nil || cfg.Slack == nil {
		return nil
	}

	clientID := strings.TrimSpace(cfg.Slack.ClientID)
	clientSecret := strings.TrimSpace(cfg.Slack.ClientSecret)
	redirectURL := strings.TrimSpace(cfg.Slack.RedirectURL)
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  slackOpenIDAuthorizeURL,
			TokenURL: slackOpenIDTokenURL,
		},
	}
}

func generateStateToken() (string, error) {
	stateTokenByteSize := 32
	raw := make([]byte, stateTokenByteSize)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate secure state token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (h *SlackLinkHandler) respondCallbackSuccess(ctx echo.Context) error {
	query := url.Values{}
	query.Set("status", "success")

	return ctx.Redirect(http.StatusFound, h.webCallbackRedirectURL(query))
}

func (h *SlackLinkHandler) respondCallbackError(ctx echo.Context, errCode string) error {
	query := url.Values{}
	query.Set("status", "error")

	if errCode != "" {
		query.Set("code", errCode)

	}

	return ctx.Redirect(http.StatusFound, h.webCallbackRedirectURL(query))
}

func (h *SlackLinkHandler) webCallbackRedirectURL(query url.Values) string {
	baseURL := ""
	if h != nil && h.config != nil {
		baseURL = strings.TrimRight(strings.TrimSpace(h.config.WebBaseURL), "/")
	}

	if len(query) == 0 {
		return baseURL + "/auth/slack/callback"
	}

	return baseURL + "/auth/slack/callback?" + query.Encode()
}

func shortStateToken(state string) string {
	trimmed := strings.TrimSpace(state)
	if len(trimmed) <= 8 {
		return trimmed
	}
	return trimmed[:8] + "..."
}
