package providers

import (
	"context"
	"fmt"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// BaseOIDCProvider implements a generic OIDC provider
type BaseOIDCProvider struct {
	config       *config.SSOProviderConfig
	oauth2Config *oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	logger       *zap.SugaredLogger
}

// NewBaseOIDCProvider creates a new generic OIDC provider
func NewBaseOIDCProvider(ctx context.Context, cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (*BaseOIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  fmt.Sprintf("%s/%s", callbackURL, cfg.Name),
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

	return &BaseOIDCProvider{
		config:       cfg,
		oauth2Config: oauth2Config,
		provider:     provider,
		verifier:     verifier,
		logger:       logger,
	}, nil
}

func (p *BaseOIDCProvider) GetAuthURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state)
}

func (p *BaseOIDCProvider) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.oauth2Config.Exchange(ctx, code)
}

func (p *BaseOIDCProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	userInfo := &types.UserInfo{
		Subject: idToken.Subject,
		Claims:  claims,
	}

	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		userInfo.FirstName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		userInfo.LastName = familyName
	}
	if hd, ok := claims["hd"].(string); ok {
		userInfo.HostedDomain = hd
	}

	// Extract groups from claims based on group mapping
	userInfo.Groups = p.extractGroups(claims)

	return userInfo, nil
}

func (p *BaseOIDCProvider) extractGroups(claims map[string]interface{}) []string {
	claimGroups := buildClaimGroups(claims)

	var mappedGroups []string
	for claimGroup := range claimGroups {
		if groups, ok := p.config.GroupMapping[claimGroup]; ok {
			mappedGroups = append(mappedGroups, groups...)
		}
	}

	return mappedGroups
}

func (p *BaseOIDCProvider) GetProviderConfig() *config.SSOProviderConfig {
	return p.config
}

func (p *BaseOIDCProvider) GetName() string {
	return p.config.Name
}

func (p *BaseOIDCProvider) GetProtocol() string {
	return "oidc"
}
