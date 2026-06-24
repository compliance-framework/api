package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var googleGroupsEndpoint = "https://www.googleapis.com/admin/directory/v1/groups?userKey=me"

// GoogleOIDCProvider extends BaseOIDCProvider with Google-specific functionality
type GoogleOIDCProvider struct {
	*BaseOIDCProvider
	logger *zap.SugaredLogger
}

// NewGoogleOIDCProvider creates a new Google OIDC provider
func NewGoogleOIDCProvider(ctx context.Context, cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (*GoogleOIDCProvider, error) {
	base, err := NewBaseOIDCProvider(ctx, cfg, callbackURL, logger)
	if err != nil {
		return nil, err
	}

	return &GoogleOIDCProvider{
		BaseOIDCProvider: base,
		logger:           logger,
	}, nil
}

// GetUserInfo extends the base implementation with Google-specific group fetching
func (p *GoogleOIDCProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error) {
	userInfo, err := p.BaseOIDCProvider.GetUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	// Fetch Google-specific groups (e.g., Google Workspace groups) as raw "google-group:<email>"
	// claim keys, then map them through group_mapping for Groups and carry the raw keys on
	// RawGroups for the DB-backed login sync (BCH-1331).
	googleGroupKeys, err := p.fetchGoogleGroupKeys(ctx, token)
	if err != nil {
		// Log error but don't fail - groups are optional
		_ = err
	} else {
		userInfo.RawGroups = append(userInfo.RawGroups, googleGroupKeys...)
		for _, key := range googleGroupKeys {
			if groups, ok := p.config.GroupMapping[key]; ok {
				userInfo.Groups = append(userInfo.Groups, groups...)
			}
		}
	}

	return userInfo, nil
}

// fetchGoogleGroupKeys fetches the user's Google Workspace groups and returns them as raw
// "google-group:<email>" claim keys (un-mapped). Mapping to native CCF groups happens in
// GetUserInfo / the DB SSOGroupMapping rows.
// Requires: https://www.googleapis.com/auth/admin.directory.group.readonly scope
func (p *GoogleOIDCProvider) fetchGoogleGroupKeys(ctx context.Context, token *oauth2.Token) ([]string, error) {
	client := p.oauth2Config.Client(ctx, token)

	resp, err := client.Get(googleGroupsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Google groups: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			p.logger.Error("failed to close Google groups response body", "error", err)
		}
	}()

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

	var keys []string
	for _, group := range groupsResponse.Groups {
		keys = append(keys, fmt.Sprintf("google-group:%s", group.Email))
	}

	return keys, nil
}
