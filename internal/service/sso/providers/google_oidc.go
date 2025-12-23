package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"golang.org/x/oauth2"
)

var googleGroupsEndpoint = "https://www.googleapis.com/admin/directory/v1/groups?userKey=me"

// GoogleOIDCProvider extends BaseOIDCProvider with Google-specific functionality
type GoogleOIDCProvider struct {
	*BaseOIDCProvider
}

// NewGoogleOIDCProvider creates a new Google OIDC provider
func NewGoogleOIDCProvider(ctx context.Context, cfg *config.SSOProviderConfig, callbackURL string) (*GoogleOIDCProvider, error) {
	base, err := NewBaseOIDCProvider(ctx, cfg, callbackURL)
	if err != nil {
		return nil, err
	}

	return &GoogleOIDCProvider{
		BaseOIDCProvider: base,
	}, nil
}

// GetUserInfo extends the base implementation with Google-specific group fetching
func (p *GoogleOIDCProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error) {
	userInfo, err := p.BaseOIDCProvider.GetUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	// Fetch Google-specific groups (e.g., Google Workspace groups)
	googleGroups, err := p.fetchGoogleGroups(ctx, token)
	if err != nil {
		// Log error but don't fail - groups are optional
		_ = err
	} else {
		userInfo.Groups = append(userInfo.Groups, googleGroups...)
	}

	return userInfo, nil
}

// fetchGoogleGroups fetches groups from Google Workspace Directory API
// Requires: https://www.googleapis.com/auth/admin.directory.group.readonly scope
func (p *GoogleOIDCProvider) fetchGoogleGroups(ctx context.Context, token *oauth2.Token) ([]string, error) {
	client := p.oauth2Config.Client(ctx, token)

	resp, err := client.Get(googleGroupsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Google groups: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			return nil, nil
		}
		return nil, fmt.Errorf("groups request failed with status %d", resp.StatusCode)
	}

	var groupsResponse struct {
		Groups []struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"groups"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&groupsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode groups response: %w", err)
	}

	var mappedGroups []string
	for _, group := range groupsResponse.Groups {
		groupKey := fmt.Sprintf("google-group:%s", group.Email)
		if groups, ok := p.config.GroupMapping[groupKey]; ok {
			mappedGroups = append(mappedGroups, groups...)
		}
	}

	return mappedGroups, nil
}
