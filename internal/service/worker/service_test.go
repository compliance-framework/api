package worker

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestNewService_Disabled(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: false,
	}
	logger := zap.NewNop().Sugar()

	service, err := NewService(cfg, nil, nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.False(t, service.IsStarted())
}

func TestNewService_RequiresEmailService(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: true,
		Workers: 5,
		Queue:   "email",
	}
	logger := zap.NewNop().Sugar()

	service, err := NewService(cfg, nil, nil, logger)
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "email service is required")
}

func TestService_EnqueueWhenDisabled(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: false,
	}
	logger := zap.NewNop().Sugar()

	service, err := NewService(cfg, nil, nil, logger)
	assert.NoError(t, err)

	ctx := context.Background()
	args := &SendEmailArgs{
		To:      []string{"test@example.com"},
		Subject: "Test",
	}

	err = service.EnqueueSendEmail(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "worker service is disabled")
}
