package sso

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/sso/providers"
	"go.uber.org/zap"
)

// CreateProvider creates a provider instance based on the configuration
func CreateProvider(cfg *config.SSOProviderConfig, callbackURL string, logger *zap.SugaredLogger) (Provider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider := strings.ToLower(cfg.Provider)
	protocol := strings.ToLower(cfg.Protocol)

	// Default protocol to oidc if not specified
	if protocol == "" {
		protocol = "oidc"
	}

	// Create provider based on provider+protocol combination
	switch {
	case provider == "google" && protocol == "oidc":
		return providers.NewGoogleOIDCProvider(ctx, cfg, callbackURL, logger)

	case provider == "github" && protocol == "oauth":
		return providers.NewGitHubOAuthProvider(cfg, callbackURL, logger)

	case provider == "generic" && protocol == "oidc":
		return providers.NewBaseOIDCProvider(ctx, cfg, callbackURL, logger)

	case provider == "generic" && protocol == "oauth":
		return providers.NewBaseOAuthProvider(cfg, callbackURL, logger)

	case protocol == "oidc":
		// Fallback to generic OIDC for unknown providers
		return providers.NewBaseOIDCProvider(ctx, cfg, callbackURL, logger)

	case protocol == "oauth":
		// Fallback to generic OAuth for unknown providers
		return providers.NewBaseOAuthProvider(cfg, callbackURL, logger)

	default:
		return nil, fmt.Errorf("unsupported provider/protocol combination: %s/%s", provider, protocol)
	}
}
