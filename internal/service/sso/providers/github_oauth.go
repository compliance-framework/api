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

var (
	githubOrganizationsEndpoint = "https://api.github.com/user/orgs"
	githubTeamsEndpoint         = "https://api.github.com/user/teams"
)

// GitHubOAuthProvider extends BaseOAuthProvider with GitHub-specific functionality
type GitHubOAuthProvider struct {
	*BaseOAuthProvider
}

// NewGitHubOAuthProvider creates a new GitHub OAuth provider
func NewGitHubOAuthProvider(cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (*GitHubOAuthProvider, error) {
	base, err := NewBaseOAuthProvider(cfg, callbackURL, logger)
	if err != nil {
		return nil, err
	}

	return &GitHubOAuthProvider{
		BaseOAuthProvider: base,
	}, nil
}

// GetUserInfo extends the base implementation with GitHub-specific group fetching
func (p *GitHubOAuthProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error) {
	userInfo, err := p.BaseOAuthProvider.GetUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	// Fetch GitHub organizations
	orgs, err := p.fetchGitHubOrganizations(ctx, token)
	if err != nil {
		_ = err
	} else {
		for _, org := range orgs {
			orgKey := fmt.Sprintf("github-organization:%s", org)
			userInfo.RawGroups = append(userInfo.RawGroups, orgKey)
			if groups, ok := p.config.GroupMapping[orgKey]; ok {
				userInfo.Groups = append(userInfo.Groups, groups...)
			}
		}
	}

	// Fetch GitHub teams
	teams, err := p.fetchGitHubTeams(ctx, token)
	if err != nil {
		_ = err
	} else {
		for _, team := range teams {
			teamKey := fmt.Sprintf("github-team:%s", team)
			userInfo.RawGroups = append(userInfo.RawGroups, teamKey)
			if groups, ok := p.config.GroupMapping[teamKey]; ok {
				userInfo.Groups = append(userInfo.Groups, groups...)
			}
		}
	}

	return userInfo, nil
}

func (p *GitHubOAuthProvider) fetchGitHubOrganizations(ctx context.Context, token *oauth2.Token) ([]string, error) {
	client := p.oauth2Config.Client(ctx, token)

	req, err := http.NewRequestWithContext(ctx, "GET", githubOrganizationsEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub organizations: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			p.logger.Error("failed to close GitHub organizations response body", "err", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("organizations request failed with status %d", resp.StatusCode)
	}

	var orgs []struct {
		Login string `json:"login"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, fmt.Errorf("failed to decode organizations response: %w", err)
	}

	var orgNames []string
	for _, org := range orgs {
		orgNames = append(orgNames, org.Login)
	}

	return orgNames, nil
}

func (p *GitHubOAuthProvider) fetchGitHubTeams(ctx context.Context, token *oauth2.Token) ([]string, error) {
	client := p.oauth2Config.Client(ctx, token)

	req, err := http.NewRequestWithContext(ctx, "GET", githubTeamsEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch GitHub teams: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			p.logger.Error("failed to close GitHub teams response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var teams []struct {
		Name         string `json:"name"`
		Slug         string `json:"slug"`
		Organization struct {
			Login string `json:"login"`
		} `json:"organization"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil {
		return nil, fmt.Errorf("failed to decode teams response: %w", err)
	}

	var teamNames []string
	for _, team := range teams {
		teamNames = append(teamNames, fmt.Sprintf("%s/%s", team.Organization.Login, team.Slug))
	}

	return teamNames, nil
}
