package email

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	emailtemplates "github.com/compliance-framework/api/internal/service/email/templates"
	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeProvider struct {
	sendResult *types.SendResult
	sendError  error
}

func (f *fakeProvider) Send(ctx context.Context, message *types.Message) (*types.SendResult, error) {
	return f.sendResult, f.sendError
}

func (f *fakeProvider) SendTemplate(ctx context.Context, template string, data interface{}, message *types.Message) (*types.SendResult, error) {
	return f.sendResult, f.sendError
}

func (f *fakeProvider) GetProviderConfig() *config.EmailProviderConfig { return nil }
func (f *fakeProvider) GetName() string                                { return "fake" }
func (f *fakeProvider) GetType() string                                { return "fake" }
func (f *fakeProvider) IsHealthy(ctx context.Context) error            { return nil }
func (f *fakeProvider) Close() error                                   { return nil }

func TestServiceSend_Disabled(t *testing.T) {
	svc := &Service{
		config: nil,
		logger: zap.NewNop().Sugar(),
	}

	result, err := svc.Send(context.Background(), &types.Message{})
	require.Error(t, err)
	require.False(t, result.Success)
	require.Equal(t, "email service is not enabled or no provider configured", result.Error)
}

func TestServiceSend_Success(t *testing.T) {
	provider := &fakeProvider{
		sendResult: &types.SendResult{Success: true},
	}

	svc := &Service{
		config:   &config.EmailConfig{Enabled: true},
		provider: provider,
		logger:   zap.NewNop().Sugar(),
	}

	result, err := svc.Send(context.Background(), &types.Message{})
	require.NoError(t, err)
	require.True(t, result.Success)
}

func TestServiceSendWithProvider_Disabled(t *testing.T) {
	svc := &Service{
		config: nil,
		logger: zap.NewNop().Sugar(),
	}

	result, err := svc.SendWithProvider(context.Background(), "smtp", &types.Message{})
	require.Error(t, err)
	require.False(t, result.Success)
	require.Equal(t, "email service is not enabled", result.Error)
}

func TestServiceSendWithProvider_ReturnsProviderError(t *testing.T) {
	defer func() { createProviderByNameFn = CreateProviderByName }()

	createProviderByNameFn = func(cfg *config.EmailConfig, name string, logger *zap.SugaredLogger) (types.Provider, error) {
		return &fakeProvider{
			sendResult: &types.SendResult{
				Success: false,
				Error:   "send error",
			},
			sendError: errors.New("send error"),
		}, nil
	}

	svc := &Service{
		config: &config.EmailConfig{
			Enabled: true,
		},
		logger: zap.NewNop().Sugar(),
	}

	result, err := svc.SendWithProvider(context.Background(), "smtp", &types.Message{})
	require.Error(t, err)
	require.False(t, result.Success)
	require.Equal(t, "send error", result.Error)
}

func TestServiceUseTemplate_NoTemplateService(t *testing.T) {
	svc := &Service{
		templateService: nil,
	}

	_, _, err := svc.UseTemplate("forgot-password", map[string]interface{}{})
	require.Error(t, err)
	require.Equal(t, "template service is not available", err.Error())
}

func TestServiceUseTemplate_Success(t *testing.T) {
	templateService, err := emailtemplates.NewTemplateService()
	require.NoError(t, err)

	svc := &Service{
		templateService: templateService,
	}

	html, text, err := svc.UseTemplate("forgot-password", map[string]interface{}{
		"FirstName": "Test",
		"ResetURL":  "http://localhost",
	})
	require.NoError(t, err)
	require.NotEmpty(t, html)
	require.NotEmpty(t, text)
}
