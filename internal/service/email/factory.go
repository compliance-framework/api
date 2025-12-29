package email

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/providers"
	"github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

// CreateProvider creates an email provider instance based on the configuration
func CreateProvider(cfg *config.EmailProviderConfig, logger *zap.SugaredLogger) (types.Provider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider := strings.ToLower(cfg.Provider)

	switch provider {
	case "smtp":
		return providers.NewSMTPProvider(ctx, cfg, logger)

	case "sendgrid":
		return providers.NewSendgridProvider(ctx, cfg, logger)

	case "ses":
		return providers.NewSESProvider(ctx, cfg, logger)

	default:
		return nil, fmt.Errorf("unsupported email provider: %s", provider)
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

	if !providerCfg.Enabled {
		return nil, fmt.Errorf("email provider %q is not enabled", name)
	}

	return CreateProvider(providerCfg, logger)
}
