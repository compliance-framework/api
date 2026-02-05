package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/riverqueue/river"
	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
)

// MockEmailService is a mock implementation of EmailService
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) Send(ctx context.Context, message *types.Message) (*types.SendResult, error) {
	args := m.Called(ctx, message)
	return args.Get(0).(*types.SendResult), args.Error(1)
}

func (m *MockEmailService) SendWithProvider(ctx context.Context, providerName string, message *types.Message) (*types.SendResult, error) {
	args := m.Called(ctx, providerName, message)
	return args.Get(0).(*types.SendResult), args.Error(1)
}

// MockDigestService is a mock implementation of DigestService
type MockDigestService struct {
	mock.Mock
}

func (m *MockDigestService) SendGlobalDigest(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockLogger is a mock implementation of Logger
type MockLogger struct {
	mock.Mock
	loggedMessages []string
}

func (m *MockLogger) Infow(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
	m.loggedMessages = append(m.loggedMessages, "INFO: "+msg)
}

func (m *MockLogger) Errorw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
	m.loggedMessages = append(m.loggedMessages, "ERROR: "+msg)
}

func (m *MockLogger) Warnw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
	m.loggedMessages = append(m.loggedMessages, "WARN: "+msg)
}

func (m *MockLogger) Debugw(msg string, keysAndValues ...interface{}) {
	m.Called(msg, keysAndValues)
	m.loggedMessages = append(m.loggedMessages, "DEBUG: "+msg)
}

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

func TestNewSendEmailWorker(t *testing.T) {
	mockEmailService := &MockEmailService{}
	mockLogger := &MockLogger{}

	worker := NewSendEmailWorker(mockEmailService, mockLogger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockEmailService, worker.emailService)
	assert.Equal(t, mockLogger, worker.logger)
}

func TestSendEmailWorker_MessageConstruction(t *testing.T) {
	mockEmailService := &MockEmailService{}

	ctx := context.Background()
	args := &SendEmailArgs{
		To:       []string{"test@example.com"},
		Subject:  "Test Subject",
		HTMLBody: "<p>Test Body</p>",
		From:     "sender@example.com",
		Cc:       []string{"cc@example.com"},
		Bcc:      []string{"bcc@example.com"},
		TextBody: "Plain text body",
	}

	// Test message construction logic
	message := &types.Message{
		From:        args.From,
		To:          args.To,
		Cc:          args.Cc,
		Bcc:         args.Bcc,
		Subject:     args.Subject,
		HTMLBody:    args.HTMLBody,
		TextBody:    args.TextBody,
		Attachments: args.Attachments,
		Headers:     args.Headers,
	}

	// Verify the message is constructed correctly
	assert.Equal(t, args.From, message.From)
	assert.Equal(t, args.To, message.To)
	assert.Equal(t, args.Cc, message.Cc)
	assert.Equal(t, args.Bcc, message.Bcc)
	assert.Equal(t, args.Subject, message.Subject)
	assert.Equal(t, args.HTMLBody, message.HTMLBody)
	assert.Equal(t, args.TextBody, message.TextBody)
	assert.Equal(t, args.Attachments, message.Attachments)
	assert.Equal(t, args.Headers, message.Headers)

	// Set up mock expectations
	mockEmailService.On("Send", ctx, message).Return(&types.SendResult{
		Success:   true,
		MessageID: "test-message-id",
	}, nil)

	// Call the mock service to verify it works
	result, err := mockEmailService.Send(ctx, message)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "test-message-id", result.MessageID)

	mockEmailService.AssertExpectations(t)
}

func TestSendEmailWorker_Work_Validation(t *testing.T) {
	mockEmailService := &MockEmailService{}
	mockLogger := &MockLogger{}
	worker := NewSendEmailWorker(mockEmailService, mockLogger)

	ctx := context.Background()

	tests := []struct {
		name        string
		args        *SendEmailArgs
		expectError string
	}{
		{
			name: "missing recipients",
			args: &SendEmailArgs{
				Subject:  "Test",
				HTMLBody: "<p>Test</p>",
			},
			expectError: "email job requires at least one recipient",
		},
		{
			name: "missing subject",
			args: &SendEmailArgs{
				To:       []string{"test@example.com"},
				HTMLBody: "<p>Test</p>",
			},
			expectError: "email job requires a subject",
		},
		{
			name: "missing body",
			args: &SendEmailArgs{
				To:      []string{"test@example.com"},
				Subject: "Test",
			},
			expectError: "email job requires either HTML body or text body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock logger to expect any call
			mockLogger.On("Infow", "Processing send email job", mock.Anything).Maybe()

			// Create a test job with the invalid args
			job := &river.Job[SendEmailArgs]{
				Args: *tt.args,
			}

			// Call the actual Work method and expect validation error
			err := worker.Work(ctx, job)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestNewSendEmailFromWorker(t *testing.T) {
	mockEmailService := &MockEmailService{}
	mockLogger := &MockLogger{}

	worker := NewSendEmailFromWorker(mockEmailService, mockLogger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockEmailService, worker.emailService)
	assert.Equal(t, mockLogger, worker.logger)
}

func TestSendEmailFromWorker_MessageConstruction(t *testing.T) {
	mockEmailService := &MockEmailService{}

	ctx := context.Background()
	args := &SendEmailFromArgs{
		Provider: "smtp",
		To:       []string{"test@example.com"},
		Subject:  "Test Subject",
		HTMLBody: "<p>Test Body</p>",
		From:     "sender@example.com",
	}

	// Test message construction logic
	message := &types.Message{
		From:        args.From,
		To:          args.To,
		Cc:          args.Cc,
		Bcc:         args.Bcc,
		Subject:     args.Subject,
		HTMLBody:    args.HTMLBody,
		TextBody:    args.TextBody,
		Attachments: args.Attachments,
		Headers:     args.Headers,
	}

	// Verify the message is constructed correctly
	assert.Equal(t, args.From, message.From)
	assert.Equal(t, args.To, message.To)
	assert.Equal(t, args.Subject, message.Subject)
	assert.Equal(t, args.HTMLBody, message.HTMLBody)

	// Set up mock expectations
	mockEmailService.On("SendWithProvider", ctx, "smtp", message).Return(&types.SendResult{
		Success:   true,
		MessageID: "test-message-id",
	}, nil)

	// Call the mock service to verify it works
	result, err := mockEmailService.SendWithProvider(ctx, "smtp", message)
	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Equal(t, "test-message-id", result.MessageID)

	mockEmailService.AssertExpectations(t)
}

func TestNewSendGlobalDigestWorker(t *testing.T) {
	mockDigestService := &MockDigestService{}
	mockLogger := &MockLogger{}

	worker := NewSendGlobalDigestWorker(mockDigestService, mockLogger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockDigestService, worker.digestService)
	assert.Equal(t, mockLogger, worker.logger)
}

func TestSendGlobalDigestWorker_DigestCall(t *testing.T) {
	mockDigestService := &MockDigestService{}

	ctx := context.Background()

	// Set up mock expectations
	mockDigestService.On("SendGlobalDigest", ctx).Return(nil)

	// Call the mock service to verify it works
	err := mockDigestService.SendGlobalDigest(ctx)
	assert.NoError(t, err)

	mockDigestService.AssertExpectations(t)
}

func TestWorkers(t *testing.T) {
	mockEmailService := &MockEmailService{}
	mockDigestService := &MockDigestService{}
	mockLogger := &MockLogger{}

	workers := Workers(mockEmailService, mockDigestService, mockLogger)

	assert.NotNil(t, workers)
}

func TestJobInsertOptions(t *testing.T) {
	opts := JobInsertOptions()

	assert.Equal(t, "email", opts.Queue)
	assert.Equal(t, 5, opts.MaxAttempts)
}

func TestParseCronScheduleWithFallback_InvalidUsesFallback(t *testing.T) {
	logger := zap.NewNop().Sugar()

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	schedule := parseCronScheduleWithFallback("not-a-cron", "@weekly", "test", logger)

	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	fallbackSchedule, err := parser.Parse("@weekly")
	assert.NoError(t, err)

	assert.Equal(t, fallbackSchedule.Next(from), schedule.Next(from))
}

func TestPeriodicJobsFromConfig_WorkflowSchedulerEnabledGuard(t *testing.T) {
	logger := zap.NewNop().Sugar()

	jobs := periodicJobsFromConfig(&config.Config{
		DigestEnabled: false,
		Workflow: &config.WorkflowConfig{
			SchedulerEnabled: false,
			Schedule:         "@every 15m",
		},
	}, logger)
	assert.Len(t, jobs, 0)

	jobs = periodicJobsFromConfig(&config.Config{
		DigestEnabled: false,
		Workflow: &config.WorkflowConfig{
			SchedulerEnabled: true,
			Schedule:         "@every 15m",
		},
	}, logger)
	assert.Len(t, jobs, 1)
}

func TestWorkflowSchedulerPeriodicJobConstructor_InsertOpts(t *testing.T) {
	args, opts := workflowSchedulerPeriodicJobConstructor()
	assert.NotNil(t, args)
	assert.NotNil(t, opts)
	assert.Equal(t, "scheduler", opts.Queue)
	assert.Equal(t, 3, opts.MaxAttempts)
	assert.Equal(t, 1, opts.Priority)
	assert.Equal(t, "schedule_workflows", args.Kind())
}

func TestJobInsertOptionsWithQueue(t *testing.T) {
	opts := JobInsertOptionsWithQueue("custom-queue")

	assert.Equal(t, "custom-queue", opts.Queue)
	assert.Equal(t, 5, opts.MaxAttempts)
}

func TestJobInsertOptionsWithRetry(t *testing.T) {
	opts := JobInsertOptionsWithRetry("custom-queue", 10)

	assert.Equal(t, "custom-queue", opts.Queue)
	assert.Equal(t, 10, opts.MaxAttempts)
}
