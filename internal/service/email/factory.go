package email

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/providers"
	"github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

// CreateProvider creates an email provider instance based on the configuration
func CreateProvider(cfg config.EmailProviderSettings, logger *zap.SugaredLogger) (types.Provider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch provider := cfg.(type) {
	case *config.SMTPConfig:
		return providers.NewSMTPProvider(ctx, provider, logger)
	case *config.SESConfig:
		return providers.NewSESProvider(ctx, provider, logger)
	default:
		return nil, fmt.Errorf("unsupported email provider type: %T", cfg)
	}
}

// CreateDefaultProvider creates the default email provider from the email config
func CreateDefaultProvider(cfg *config.EmailConfig, logger *zap.SugaredLogger) (types.Provider, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("email is not enabled")
	}

	providerCfg := cfg.GetDefaultProvider()
	if providerCfg == nil {
		return nil, fmt.Errorf("no enabled email provider found")
	}

	return CreateProvider(providerCfg, logger)
}

// CreateProviderByName creates a specific email provider by name
func CreateProviderByName(cfg *config.EmailConfig, name string, logger *zap.SugaredLogger) (types.Provider, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("email is not enabled")
	}

	providerCfg := cfg.GetProvider(name)
	if providerCfg == nil {
		return nil, fmt.Errorf("email provider %q not found", name)
	}

	if !providerCfg.IsEnabled() {
		return nil, fmt.Errorf("email provider %q is not enabled", name)
	}

	return CreateProvider(providerCfg, logger)
}
