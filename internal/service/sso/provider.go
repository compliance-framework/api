package sso

import (
	"context"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"golang.org/x/oauth2"
)

// Provider defines the interface that all SSO providers must implement
type Provider interface {
	// GetAuthURL returns the authorization URL for the OAuth2 flow
	GetAuthURL(state string) string

	// ExchangeCode exchanges an authorization code for a token
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)

	// GetUserInfo retrieves user information using the provided token
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error)

	// GetProviderConfig returns the provider configuration
	GetProviderConfig() *config.SSOProviderConfig

	// GetName returns the provider name
	GetName() string

	// GetProtocol returns the protocol (oidc or oauth)
	GetProtocol() string
}
