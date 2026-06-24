package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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
	provider, err := newOIDCProvider(ctx, cfg)
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

func newOIDCProvider(ctx context.Context, cfg *config.SSOProviderConfig) (*oidc.Provider, error) {
	wellKnownURL := strings.TrimSpace(cfg.WellKnownURL)
	if wellKnownURL == "" {
		return oidc.NewProvider(ctx, cfg.IssuerURL)
	}

	providerConfig, err := fetchOIDCProviderConfig(ctx, wellKnownURL)
	if err != nil {
		return nil, err
	}
	if providerConfig.IssuerURL != cfg.IssuerURL {
		return nil, fmt.Errorf("oidc: configured issuer URL %q did not match the issuer URL returned by provider %q", cfg.IssuerURL, providerConfig.IssuerURL)
	}
	internalIssuerURL, err := issuerURLFromWellKnownURL(wellKnownURL)
	if err != nil {
		return nil, err
	}
	rewriteServerSideOIDCEndpoints(providerConfig, cfg.IssuerURL, internalIssuerURL)

	return providerConfig.NewProvider(ctx), nil
}

func fetchOIDCProviderConfig(ctx context.Context, wellKnownURL string) (*oidc.ProviderConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	client := http.DefaultClient
	if configuredClient, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && configuredClient != nil {
		client = configuredClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var providerConfig oidc.ProviderConfig
	if err := json.Unmarshal(body, &providerConfig); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider discovery object: %w", err)
	}
	return &providerConfig, nil
}

func issuerURLFromWellKnownURL(wellKnownURL string) (string, error) {
	parsedURL, err := url.Parse(wellKnownURL)
	if err != nil {
		return "", err
	}

	wellKnownPath := "/.well-known/openid-configuration"
	if !strings.HasSuffix(parsedURL.Path, wellKnownPath) {
		return "", fmt.Errorf("well_known_url %q must end with %s", wellKnownURL, wellKnownPath)
	}

	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, wellKnownPath)
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""
	return strings.TrimSuffix(parsedURL.String(), "/"), nil
}

func rewriteServerSideOIDCEndpoints(providerConfig *oidc.ProviderConfig, publicIssuerURL string, internalIssuerURL string) {
	providerConfig.TokenURL = rewriteIssuerURL(providerConfig.TokenURL, publicIssuerURL, internalIssuerURL)
	providerConfig.UserInfoURL = rewriteIssuerURL(providerConfig.UserInfoURL, publicIssuerURL, internalIssuerURL)
	providerConfig.JWKSURL = rewriteIssuerURL(providerConfig.JWKSURL, publicIssuerURL, internalIssuerURL)
}

func rewriteIssuerURL(value string, publicIssuerURL string, internalIssuerURL string) string {
	if value == "" {
		return ""
	}

	publicIssuerURL = strings.TrimSuffix(publicIssuerURL, "/")
	if value == publicIssuerURL {
		return internalIssuerURL
	}
	if strings.HasPrefix(value, publicIssuerURL+"/") {
		return internalIssuerURL + strings.TrimPrefix(value, publicIssuerURL)
	}
	return value
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
	if userInfo.FirstName == "" && userInfo.LastName == "" {
		userInfo.FirstName, userInfo.LastName = splitDisplayName(userInfo.Name)
	}
	if hd, ok := claims["hd"].(string); ok {
		userInfo.HostedDomain = hd
	}

	// Extract groups from claims based on group mapping
	userInfo.Groups = p.extractGroups(claims)
	// Carry the raw claim-group identifiers so the login sync can translate them through the DB
	// SSOGroupMapping rows (BCH-1331), independent of the config group_mapping above.
	userInfo.RawGroups = claimGroupKeys(claims)

	return userInfo, nil
}

func splitDisplayName(name string) (string, string) {
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.Join(parts[1:], " ")
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
