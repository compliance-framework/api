package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/types"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var providerFactory = CreateProvider

// Service manages SSO authentication using the provider interface pattern
type Service struct {
	config    *config.SSOConfig
	logger    *zap.SugaredLogger
	providers map[string]Provider // Provider interface instances
}

// IsEnabled returns whether SSO is enabled
func (s *Service) IsEnabled() bool {
	return s.config != nil && s.config.Enabled
}

// NewService creates a new SSO service with configured providers
func NewService(cfg *config.SSOConfig, logger *zap.SugaredLogger) (*Service, error) {
	service := &Service{
		config:    cfg,
		logger:    logger,
		providers: make(map[string]Provider),
	}

	if cfg == nil || !cfg.Enabled {
		logger.Info("SSO is disabled")
		return service, nil
	}

	// Initialize each enabled provider using the factory
	for i := range cfg.Providers {
		providerConfig := cfg.Providers[i]
		if !providerConfig.Enabled {
			continue
		}

		provider, err := providerFactory(&providerConfig, cfg.CallbackURL)
		if err != nil {
			logger.Errorw("Failed to initialize SSO provider",
				"provider", providerConfig.Name,
				"protocol", providerConfig.Protocol,
				"error", err)
			continue
		}

		service.providers[providerConfig.Name] = provider
		logger.Infow("Initialized SSO provider",
			"provider", providerConfig.Name,
			"protocol", provider.GetProtocol())
	}

	return service, nil
}

// GetAuthURL returns the authorization URL for a given provider
func (s *Service) GetAuthURL(providerName string, state string) (string, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return "", fmt.Errorf("provider %s not configured", providerName)
	}

	return provider.GetAuthURL(state), nil
}

// ExchangeCode exchanges an authorization code for a token
func (s *Service) ExchangeCode(ctx context.Context, providerName string, code string) (*oauth2.Token, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("provider %s not configured", providerName)
	}

	return provider.ExchangeCode(ctx, code)
}

// GetUserInfo retrieves user information from the provider
func (s *Service) GetUserInfo(ctx context.Context, providerName string, token *oauth2.Token) (*types.UserInfo, error) {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("provider %s not configured", providerName)
	}

	return provider.GetUserInfo(ctx, token)
}

// GetProviderConfig returns the configuration for a specific provider
func (s *Service) GetProviderConfig(providerName string) *config.SSOProviderConfig {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil
	}

	return provider.GetProviderConfig()
}

// GetEnabledProviders returns a list of all enabled provider configurations
func (s *Service) GetEnabledProviders() []config.SSOProviderConfig {
	if s.config == nil {
		return nil
	}
	return s.config.GetEnabledProviders()
}

// GenerateStateToken generates a secure random state token for OAuth2 flow
func (s *Service) GenerateStateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateState is an alias for GenerateStateToken for backward compatibility
func (s *Service) GenerateState() (string, error) {
	return s.GenerateStateToken()
}

// GetOAuth2Config returns the OAuth2 config for a provider (for backward compatibility)
// Returns true if the provider exists
func (s *Service) GetOAuth2Config(providerName string) (*oauth2.Config, bool) {
	provider, ok := s.providers[providerName]
	if !ok {
		return nil, false
	}
	// Return a placeholder - the actual OAuth2Config is internal to the provider
	// The handler just needs to know if the provider exists
	_ = provider
	return &oauth2.Config{}, true
}

// CanCreateUser checks if a user can be auto-created based on group membership
func (s *Service) CanCreateUser(userInfo *types.UserInfo, providerConfig *config.SSOProviderConfig) bool {
	if providerConfig == nil {
		return false
	}

	// If no required login groups are configured, allow creation
	if len(providerConfig.RequiredLoginGroups) == 0 {
		return true
	}

	// Check if user belongs to at least one required login group
	userGroupSet := make(map[string]struct{})
	for _, g := range userInfo.Groups {
		normalized := strings.TrimSpace(strings.ToLower(g))
		if normalized != "" {
			userGroupSet[normalized] = struct{}{}
		}
	}

	for _, required := range providerConfig.RequiredLoginGroups {
		normalized := strings.TrimSpace(strings.ToLower(required))
		if _, ok := userGroupSet[normalized]; ok {
			return true
		}
	}

	return false
}

// MapUserAttributes maps user groups to internal user attributes based on provider configuration
func (s *Service) MapUserAttributes(userInfo *types.UserInfo, providerConfig *config.SSOProviderConfig) []string {
	if providerConfig == nil || len(providerConfig.GroupMapping) == 0 {
		return nil
	}

	// User groups are already mapped by the provider's GetUserInfo method
	// This method is kept for backward compatibility and additional attribute mapping if needed
	return userInfo.Groups
}

// SerializeStringArray converts a string slice to a comma-separated string
func SerializeStringArray(arr []string) string {
	if len(arr) == 0 {
		return ""
	}
	return strings.Join(arr, ",")
}

// DeserializeStringArray converts a comma-separated string to a string slice
func DeserializeStringArray(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	arr := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			arr = append(arr, trimmed)
		}
	}
	return arr
}
