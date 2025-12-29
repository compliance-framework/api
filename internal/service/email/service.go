package email

import (
	"context"
	"fmt"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/templates"
	"github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

// Service provides email functionality
type Service struct {
	config          *config.EmailConfig
	provider        types.Provider
	logger          *zap.SugaredLogger
	templateService *templates.TemplateService
}

// NewService creates a new email service
func NewService(cfg *config.EmailConfig, logger *zap.SugaredLogger) (*Service, error) {
	templateService, err := templates.NewTemplateService()
	if err != nil {
		logger.Warnw("Failed to initialize template service", "error", err)
		// Continue without template service - it's optional
	}

	if cfg == nil || !cfg.Enabled {
		return &Service{
			config:          cfg,
			logger:          logger,
			templateService: templateService,
		}, nil
	}

	provider, err := CreateDefaultProvider(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &Service{
		config:          cfg,
		provider:        provider,
		logger:          logger,
		templateService: templateService,
	}, nil
}

// Send sends an email using the default provider
func (s *Service) Send(ctx context.Context, message *types.Message) (*types.SendResult, error) {
	if s.provider == nil {
		return &types.SendResult{
			Success: false,
			Error:   "email service is not enabled or no provider configured",
		}, nil
	}

	return s.provider.Send(ctx, message)
}

// SendTemplate sends an email using a template
func (s *Service) SendTemplate(ctx context.Context, template string, data interface{}, message *types.Message) (*types.SendResult, error) {
	if s.provider == nil {
		return &types.SendResult{
			Success: false,
			Error:   "email service is not enabled or no provider configured",
		}, nil
	}

	return s.provider.SendTemplate(ctx, template, data, message)
}

// SendWithProvider sends an email using a specific provider
func (s *Service) SendWithProvider(ctx context.Context, providerName string, message *types.Message) (*types.SendResult, error) {
	if s.config == nil || !s.config.Enabled {
		return &types.SendResult{
			Success: false,
			Error:   "email service is not enabled",
		}, nil
	}

	provider, err := CreateProviderByName(s.config, providerName, s.logger)
	if err != nil {
		return &types.SendResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	return provider.Send(ctx, message)
}

// IsEnabled returns true if the email service is enabled
func (s *Service) IsEnabled() bool {
	return s.config != nil && s.config.Enabled && s.provider != nil
}

// IsHealthy checks if the email service is healthy
func (s *Service) IsHealthy(ctx context.Context) error {
	if s.provider == nil {
		return nil // Service is disabled, consider it healthy
	}

	return s.provider.IsHealthy(ctx)
}

// GetConfig returns the email configuration
func (s *Service) GetConfig() *config.EmailConfig {
	return s.config
}

// Close closes the email service and releases resources
func (s *Service) Close() error {
	if s.provider != nil {
		return s.provider.Close()
	}
	return nil
}

// UseTemplate renders a template with the given data and returns both HTML and text versions
func (s *Service) UseTemplate(templateName string, data map[string]interface{}) (htmlContent, textContent string, err error) {
	if s.templateService == nil {
		return "", "", fmt.Errorf("template service is not available")
	}

	// Convert the data to the correct type
	templateData := make(templates.TemplateData)
	for k, v := range data {
		templateData[k] = v
	}

	return s.templateService.Use(templateName, templateData)
}
