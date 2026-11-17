package sso

import (
	"context"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"golang.org/x/oauth2"
)

// Provider defines the interface that all SSO providers must implement
type Provider interface {
	// GetAuthURL returns the authorization URL for the OAuth2 flow. codeVerifier is the PKCE
	// verifier for this login; providers that do not use PKCE ignore it.
	GetAuthURL(state string, codeVerifier string) string

	// ExchangeCode exchanges an authorization code for a token. codeVerifier is the PKCE
	// verifier generated for this login; providers that do not use PKCE ignore it.
	ExchangeCode(ctx context.Context, code string, codeVerifier string) (*oauth2.Token, error)

	// UsesPKCE reports whether the provider protects the code exchange with PKCE, i.e. whether a
	// login needs a code verifier.
	UsesPKCE() bool

	// GetUserInfo retrieves user information using the provided token
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*types.UserInfo, error)

	// GetProviderConfig returns the provider configuration
	GetProviderConfig() *config.SSOProviderConfig

	// GetName returns the provider name
	GetName() string

	// GetProtocol returns the protocol (oidc or oauth)
	GetProtocol() string
}
