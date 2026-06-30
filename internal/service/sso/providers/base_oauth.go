package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// BaseOAuthProvider implements a generic OAuth2 provider
type BaseOAuthProvider struct {
	config       *config.SSOProviderConfig
	oauth2Config *oauth2.Config
	logger       *zap.SugaredLogger
}

// NewBaseOAuthProvider creates a new generic OAuth2 provider
func NewBaseOAuthProvider(cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (*BaseOAuthProvider, error) {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/%s", callbackURL, cfg.Name),
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.AuthURL,
			TokenURL: cfg.TokenURL,
		},
	}

	return &BaseOAuthProvider{
		config:       cfg,
		oauth2Config: oauth2Config,
		logger:       logger,
	}, nil
}

func (p *BaseOAuthProvider) GetAuthURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state)
}

func (p *BaseOAuthProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauth2Config.Exchange(ctx, code)
}

func (p *BaseOAuthProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error) {
	client := p.oauth2Config.Client(ctx, token)

	resp, err := client.Get(p.config.UserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			p.logger.Error("failed to close user info response body", "err", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfoData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfoData); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	userInfo := &types.UserInfo{
		Claims: userInfoData,
	}

	if id, ok := userInfoData["id"].(float64); ok {
		userInfo.Subject = fmt.Sprintf("%d", int64(id))
	} else if id, ok := userInfoData["id"].(string); ok {
		userInfo.Subject = id
	}

	if email, ok := userInfoData["email"].(string); ok {
		userInfo.Email = email
	}

	if name, ok := userInfoData["name"].(string); ok {
		userInfo.Name = name
	}

	// Extract first and last name if available
	// GitHub doesn't provide given_name/family_name, so we'll try to parse the name field
	if firstName, ok := userInfoData["given_name"].(string); ok {
		userInfo.FirstName = firstName
	}
	if lastName, ok := userInfoData["family_name"].(string); ok {
		userInfo.LastName = lastName
	}

	// If we have a full name but no first/last name, try to split it
	if userInfo.Name != "" && userInfo.FirstName == "" && userInfo.LastName == "" {
		p.parseFullName(userInfo)
	}

	if p.config.EmailURL != "" && userInfo.Email == "" {
		email, err := p.fetchEmail(ctx, client)
		if err == nil && email != "" {
			userInfo.Email = email
		}
	}

	userInfo.Groups = p.extractGroups(userInfoData)
	// Carry the raw claim-group identifiers for the login sync to translate via the DB (BCH-1331).
	userInfo.RawGroups = claimGroupKeys(userInfoData)

	return userInfo, nil
}

func (p *BaseOAuthProvider) fetchEmail(ctx context.Context, client *http.Client) (string, error) {
	resp, err := client.Get(p.config.EmailURL)
	if err != nil {
		return "", err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			p.logger.Error("failed to close email response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("email request failed with status %d", resp.StatusCode)
	}

	var emails []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, emailData := range emails {
		if primary, ok := emailData["primary"].(bool); ok && primary {
			if email, ok := emailData["email"].(string); ok {
				return email, nil
			}
		}
	}

	if len(emails) > 0 {
		if email, ok := emails[0]["email"].(string); ok {
			return email, nil
		}
	}

	return "", nil
}

func (p *BaseOAuthProvider) extractGroups(claims map[string]interface{}) []string {
	return mapClaimGroups(p.config.GroupMapping, claims)
}

func (p *BaseOAuthProvider) GetProviderConfig() *config.SSOProviderConfig {
	return p.config
}

func (p *BaseOAuthProvider) GetName() string {
	return p.config.Name
}

func (p *BaseOAuthProvider) GetProtocol() string {
	return "oauth"
}

// parseFullName attempts to split a full name into first and last name
func (p *BaseOAuthProvider) parseFullName(userInfo *types.UserInfo) {
	if userInfo.Name == "" {
		return
	}

	// Simple split on first space
	// This won't handle all cases perfectly, but works for most common formats
	parts := strings.Fields(userInfo.Name)
	if len(parts) == 0 {
		return
	}

	if len(parts) == 1 {
		userInfo.FirstName = parts[0]
		return
	}

	// First part is first name, rest is last name
	userInfo.FirstName = parts[0]
	userInfo.LastName = strings.Join(parts[1:], " ")
}
