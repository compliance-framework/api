package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

type sendgridProvider struct {
	config *config.EmailProviderConfig
	logger *zap.SugaredLogger
}

// NewSendgridProvider creates a new SendGrid email provider
func NewSendgridProvider(ctx context.Context, cfg *config.EmailProviderConfig, logger *zap.SugaredLogger) (types.Provider, error) {
	if strings.ToLower(cfg.Provider) != "sendgrid" {
		return nil, fmt.Errorf("invalid provider type for SendGrid: %s", cfg.Provider)
	}

	provider := &sendgridProvider{
		config: cfg,
		logger: logger,
	}

	logger.Infow("SendGrid provider initialized", "name", cfg.Name)
	return provider, nil
}

func (p *sendgridProvider) Send(ctx context.Context, message *types.Message) (*types.SendResult, error) {
	return nil, fmt.Errorf("SendGrid provider not implemented yet")
}

func (p *sendgridProvider) SendTemplate(ctx context.Context, template string, data interface{}, message *types.Message) (*types.SendResult, error) {
	return nil, fmt.Errorf("SendGrid provider not implemented yet")
}

func (p *sendgridProvider) GetProviderConfig() *config.EmailProviderConfig {
	return p.config
}

func (p *sendgridProvider) GetName() string {
	return p.config.Name
}

func (p *sendgridProvider) GetType() string {
	return "sendgrid"
}

func (p *sendgridProvider) IsHealthy(ctx context.Context) error {
	return fmt.Errorf("SendGrid provider not implemented yet")
}

func (p *sendgridProvider) Close() error {
	return nil
}
