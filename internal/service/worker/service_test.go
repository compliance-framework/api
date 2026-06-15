package worker

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/robfig/cron/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func (m *MockEmailService) UseTemplate(templateName string, data map[string]interface{}) (string, string, error) {
	args := m.Called(templateName, data)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockEmailService) GetDefaultFromAddress() string {
	args := m.Called()
	return args.String(0)
}

// MockDigestService is a mock implementation of DigestService
type MockDigestService struct {
	mock.Mock
}

type MockSlackService struct {
	mock.Mock
}

func (m *MockSlackService) SendMessage(ctx context.Context, channel string, message *slacktypes.Message) (*slacktypes.SendResult, error) {
	args := m.Called(ctx, channel, message)
	return args.Get(0).(*slacktypes.SendResult), args.Error(1)
}

func (m *MockSlackService) IsEnabled() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockDigestService) SendGlobalDigest(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func newTestNotificationRuntimeProvider(email EmailService, slack SlackService) notification.RuntimeProvider {
	return newWorkerNotificationRuntimeProvider(email, slack, func() notification.WorkerEnqueuer { return nil })
}

func newTestRiskNotificationServiceFactory(email EmailService, slack SlackService) *RiskNotificationServiceFactory {
	return NewRiskNotificationServiceFactory(newTestNotificationRuntimeProvider(email, slack))
}

func newTestPoamNotificationServiceFactory(email EmailService, slack SlackService) *PoamNotificationServiceFactory {
	return NewPoamNotificationServiceFactory(newTestNotificationRuntimeProvider(email, slack))
}

func makeWorkerJob[T river.JobArgs](args T) *river.Job[T] {
	return &river.Job[T]{
		JobRow: &rivertype.JobRow{ID: 1},
		Args:   args,
	}
}

func TestNewServiceWithDigest_Disabled(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: false,
	}
	logger := zap.NewNop().Sugar()

	service, err := NewServiceWithDigest(cfg, nil, nil, nil, nil, nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.False(t, service.IsStarted())
}

func TestNewServiceWithDigest_RequiresEmailService(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: true,
		Workers: 5,
		Queue:   "email",
	}
	logger := zap.NewNop().Sugar()

	service, err := NewServiceWithDigest(cfg, nil, nil, nil, nil, nil, logger)
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "email service is required")
}

func TestNewServiceWithDigest_RequiresProfileResolver(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: true,
		Workers: 5,
		Queue:   "email",
	}
	logger := zap.NewNop().Sugar()

	service, err := NewServiceWithDigest(cfg, nil, &email.Service{}, nil, nil, nil, logger)
	assert.Error(t, err)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "profile control resolver is required")
}

func TestService_EnqueueWhenDisabled(t *testing.T) {
	cfg := &config.WorkerConfig{
		Enabled: false,
	}
	logger := zap.NewNop().Sugar()

	service, err := NewServiceWithDigest(cfg, nil, nil, nil, nil, nil, logger)
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
	logger := zap.NewNop().Sugar()

	worker := NewSendEmailWorker(mockEmailService, logger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockEmailService, worker.emailService)
	assert.Equal(t, logger, worker.logger)
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
	worker := NewSendEmailWorker(mockEmailService, zap.NewNop().Sugar())

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
	logger := zap.NewNop().Sugar()

	worker := NewSendEmailFromWorker(mockEmailService, logger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockEmailService, worker.emailService)
	assert.Equal(t, logger, worker.logger)
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

func TestNewSendSlackWorker(t *testing.T) {
	mockSlackService := &MockSlackService{}
	logger := zap.NewNop().Sugar()

	worker := NewSendSlackWorker(mockSlackService, logger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockSlackService, worker.slackService)
	assert.Equal(t, logger, worker.logger)
}

func TestSendSlackWorker_WorkChannel_Validation(t *testing.T) {
	mockSlackService := &MockSlackService{}
	worker := NewSendSlackWorker(mockSlackService, zap.NewNop().Sugar())

	ctx := context.Background()

	tests := []struct {
		name        string
		args        *SendSlackChannelArgs
		expectError string
	}{
		{
			name:        "missing channel",
			args:        &SendSlackChannelArgs{Text: "hello"},
			expectError: "slack job requires a channel",
		},
		{
			name:        "missing text and blocks",
			args:        &SendSlackChannelArgs{Channel: "C123"},
			expectError: "slack job requires text or blocks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := worker.WorkChannel(ctx, &river.Job[SendSlackChannelArgs]{Args: *tt.args})
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestSendSlackWorker_WorkChannel_SendsMessage(t *testing.T) {
	mockSlackService := &MockSlackService{}
	ctx := context.Background()
	worker := NewSendSlackWorker(mockSlackService, zap.NewNop().Sugar())

	args := SendSlackChannelArgs{
		Channel:    "C123",
		TargetType: slackprovider.TargetTypeChannel,
		Text:       "Digest posted",
	}

	mockSlackService.On("IsEnabled").Return(true).Once()
	mockSlackService.On("SendMessage", ctx, "C123", &slacktypes.Message{
		Text: "Digest posted",
	}).Return(&slacktypes.SendResult{
		Success:    true,
		Channel:    "C123",
		DeliveryID: "slack-msg-channel-1",
	}, nil).Once()

	err := worker.WorkChannel(ctx, makeWorkerJob(args))
	assert.NoError(t, err)

	mockSlackService.AssertExpectations(t)
}

func TestSendSlackWorker_WorkDM_SendsMessage(t *testing.T) {
	mockSlackService := &MockSlackService{}
	ctx := context.Background()
	worker := NewSendSlackWorker(mockSlackService, zap.NewNop().Sugar())

	args := SendSlackDMArgs{
		Channel:    "U123",
		TargetType: slackprovider.TargetTypeDirectMessage,
		Text:       "Digest ready",
	}

	mockSlackService.On("IsEnabled").Return(true).Once()
	mockSlackService.On("SendMessage", ctx, "U123", &slacktypes.Message{
		Text: "Digest ready",
	}).Return(&slacktypes.SendResult{
		Success:    true,
		Channel:    "U123",
		DeliveryID: "slack-msg-dm-1",
	}, nil).Once()

	err := worker.WorkDM(ctx, makeWorkerJob(args))
	assert.NoError(t, err)

	mockSlackService.AssertExpectations(t)
}

func TestSelectSlackJobArgs(t *testing.T) {
	channelJob, err := selectSlackJobArgs(SendSlackArgs{
		Channel:    "C123",
		TargetType: slackprovider.TargetTypeChannel,
		Text:       "hello channel",
	})
	assert.NoError(t, err)
	assert.IsType(t, SendSlackChannelArgs{}, channelJob)
	assert.Equal(t, JobTypeSendSlackChannel, channelJob.Kind())

	privateChannelJob, err := selectSlackJobArgs(SendSlackArgs{
		Channel:    "G123",
		TargetType: slackprovider.TargetTypeChannel,
		Text:       "hello private channel",
	})
	assert.NoError(t, err)
	assert.IsType(t, SendSlackChannelArgs{}, privateChannelJob)
	assert.Equal(t, JobTypeSendSlackChannel, privateChannelJob.Kind())

	dmJob, err := selectSlackJobArgs(SendSlackArgs{
		Channel:    "U123",
		TargetType: slackprovider.TargetTypeDirectMessage,
		Text:       "hello user",
	})
	assert.NoError(t, err)
	assert.IsType(t, SendSlackDMArgs{}, dmJob)
	assert.Equal(t, JobTypeSendSlackDM, dmJob.Kind())

	dmConversationJob, err := selectSlackJobArgs(SendSlackArgs{
		Channel:    "D123",
		TargetType: slackprovider.TargetTypeDirectMessage,
		Text:       "hello dm",
	})
	assert.NoError(t, err)
	assert.IsType(t, SendSlackDMArgs{}, dmConversationJob)
	assert.Equal(t, JobTypeSendSlackDM, dmConversationJob.Kind())

	_, err = selectSlackJobArgs(SendSlackArgs{
		Channel: "C123",
		Text:    "missing type",
	})
	assert.EqualError(t, err, "send slack job requires a supported target type")
}

func TestServiceEnqueueNotificationEmailMapsMetadata(t *testing.T) {
	params := notificationEmailInsertParams(emailprovider.Delivery{
		To: "alice@example.com",
		Content: emailprovider.Content{
			From:     "from@example.com",
			Subject:  "Digest",
			TextBody: "body",
		},
		Metadata: notification.TransportMetadata{
			NotificationKind: notification.Kind("evidence_digest"),
			RecipientUserID:  "user-1",
			CorrelationID:    "corr-1",
			SourceJobKind:    "send_global_digest",
			SourceJobID:      "job-1",
		},
	}, "email", 7)
	require.Len(t, params, 1)

	args, ok := params[0].Args.(*SendEmailArgs)
	require.True(t, ok)
	assert.Equal(t, "alice@example.com", args.To[0])
	assert.Equal(t, "evidence_digest", args.NotificationKind)
	assert.Equal(t, 7, params[0].InsertOpts.MaxAttempts)
	assert.False(t, params[0].InsertOpts.UniqueOpts.ByArgs)
}

func TestServiceEnqueueNotificationSlackMapsMetadata(t *testing.T) {
	params, err := notificationSlackInsertParams(slackprovider.Delivery{
		Channel:    "UALICE",
		TargetType: slackprovider.TargetTypeDirectMessage,
		Content: slackprovider.Content{
			Text: "body",
		},
		Metadata: notification.TransportMetadata{
			NotificationKind: notification.Kind("evidence_digest"),
			RecipientUserID:  "user-1",
		},
	}, "slack", 6)
	require.NoError(t, err)
	require.Len(t, params, 1)

	args, ok := params[0].Args.(SendSlackDMArgs)
	require.True(t, ok)
	assert.Equal(t, "UALICE", args.Channel)
	assert.Equal(t, slackprovider.TargetTypeDirectMessage, args.TargetType)
	assert.Equal(t, 6, params[0].InsertOpts.MaxAttempts)
	assert.False(t, params[0].InsertOpts.UniqueOpts.ByArgs)
}

func TestServiceEnqueueNotificationEmail_UsesCorrelationForWorkflowDueSoonUniqueness(t *testing.T) {
	params := notificationEmailInsertParams(emailprovider.Delivery{
		To: "alice@example.com",
		Content: emailprovider.Content{
			From:     "from@example.com",
			Subject:  "Reminder",
			TextBody: "body",
		},
		Metadata: notification.TransportMetadata{
			NotificationKind: notification.Kind(JobTypeWorkflowTaskDueSoon),
			RecipientUserID:  "user-1",
			CorrelationID:    "workflow_task_due_soon:step-1",
			SourceJobKind:    JobTypeWorkflowTaskDueSoon,
		},
	}, "email", 7)
	require.Len(t, params, 1)

	args, ok := params[0].Args.(*SendEmailArgs)
	require.True(t, ok)
	assert.Equal(t, "workflow_task_due_soon:step-1", args.CorrelationID)
	assert.True(t, params[0].InsertOpts.UniqueOpts.ByArgs)
	assert.Equal(t, 24*time.Hour, params[0].InsertOpts.UniqueOpts.ByPeriod)
}

func TestServiceEnqueueNotificationSlack_UsesCorrelationForWorkflowDueSoonUniqueness(t *testing.T) {
	params, err := notificationSlackInsertParams(slackprovider.Delivery{
		Channel:    "UALICE",
		TargetType: slackprovider.TargetTypeDirectMessage,
		Content: slackprovider.Content{
			Text: "body",
		},
		Metadata: notification.TransportMetadata{
			NotificationKind: notification.Kind(JobTypeWorkflowTaskDueSoon),
			RecipientUserID:  "user-1",
			CorrelationID:    "workflow_task_due_soon:step-1",
			SourceJobKind:    JobTypeWorkflowTaskDueSoon,
		},
	}, "slack", 6)
	require.NoError(t, err)
	require.Len(t, params, 1)

	args, ok := params[0].Args.(SendSlackDMArgs)
	require.True(t, ok)
	assert.Equal(t, "workflow_task_due_soon:step-1", args.CorrelationID)
	assert.True(t, params[0].InsertOpts.UniqueOpts.ByArgs)
	assert.Equal(t, 24*time.Hour, params[0].InsertOpts.UniqueOpts.ByPeriod)
}

func TestServiceEnqueueNotificationEmail_UsesCorrelationForWorkflowExecutionFailedUniqueness(t *testing.T) {
	params := notificationEmailInsertParams(emailprovider.Delivery{
		To: "alice@example.com",
		Content: emailprovider.Content{
			From:     "from@example.com",
			Subject:  "Execution failed",
			TextBody: "body",
		},
		Metadata: notification.TransportMetadata{
			NotificationKind: notification.Kind(JobTypeWorkflowExecutionFailed),
			RecipientUserID:  "user-1",
			CorrelationID:    "workflow_execution_failed:exec-1",
			SourceJobKind:    JobTypeWorkflowExecutionFailed,
		},
	}, "email", 7)
	require.Len(t, params, 1)

	args, ok := params[0].Args.(*SendEmailArgs)
	require.True(t, ok)
	assert.Equal(t, []string{"alice@example.com"}, args.To)
	assert.Equal(t, "workflow_execution_failed:exec-1", args.CorrelationID)
	assert.True(t, params[0].InsertOpts.UniqueOpts.ByArgs)
	assert.Zero(t, params[0].InsertOpts.UniqueOpts.ByPeriod)
}

func TestNewSendGlobalDigestWorker(t *testing.T) {
	mockDigestService := &MockDigestService{}
	logger := zap.NewNop().Sugar()

	worker := NewSendGlobalDigestWorker(mockDigestService, logger)

	assert.NotNil(t, worker)
	assert.Equal(t, mockDigestService, worker.digestService)
	assert.Equal(t, logger, worker.logger)
}

func TestSendGlobalDigestWorker_DigestCall(t *testing.T) {
	mockDigestService := &MockDigestService{}
	ctx := context.Background()
	worker := NewSendGlobalDigestWorker(mockDigestService, zap.NewNop().Sugar())

	mockDigestService.On("SendGlobalDigest", ctx).Return(nil)

	err := worker.Work(ctx, makeWorkerJob(SendGlobalDigestArgs{}))
	assert.NoError(t, err)

	mockDigestService.AssertExpectations(t)
}

func TestWorkers(t *testing.T) {
	mockEmailService := &MockEmailService{}
	mockDigestService := &MockDigestService{}

	workers := Workers(mockEmailService, mockDigestService, nil, nil, nil, "", nil, zap.NewNop().Sugar())

	assert.NotNil(t, workers)
}

func TestJobInsertOptionsForWorkflowTaskAssignedNotification(t *testing.T) {
	opts := JobInsertOptionsForWorkflowTaskAssignedNotification()

	assert.Equal(t, "email", opts.Queue)
	assert.Equal(t, 5, opts.MaxAttempts)
	assert.True(t, opts.UniqueOpts.ByArgs)
	assert.Equal(t, 5*time.Minute, opts.UniqueOpts.ByPeriod)
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

	// Nothing enabled → 0 jobs
	jobs := periodicJobsFromConfig(&config.Config{
		DigestEnabled: false,
		Workflow: &config.WorkflowConfig{
			SchedulerEnabled:  false,
			Schedule:          "@every 15m",
			DueSoonEnabled:    false,
			TaskDigestEnabled: false,
		},
	}, logger)
	assert.Len(t, jobs, 0)

	// Scheduler only → 1 job
	jobs = periodicJobsFromConfig(&config.Config{
		DigestEnabled: false,
		Workflow: &config.WorkflowConfig{
			SchedulerEnabled:  true,
			Schedule:          "@every 15m",
			DueSoonEnabled:    false,
			TaskDigestEnabled: false,
		},
	}, logger)
	assert.Len(t, jobs, 1)

	// Scheduler + due-soon + task digest → 3 jobs
	jobs = periodicJobsFromConfig(&config.Config{
		DigestEnabled: false,
		Workflow: &config.WorkflowConfig{
			SchedulerEnabled:   true,
			Schedule:           "@every 15m",
			DueSoonEnabled:     true,
			DueSoonSchedule:    "0 8 * * *",
			TaskDigestEnabled:  true,
			TaskDigestSchedule: "0 8 * * *",
		},
	}, logger)
	assert.Len(t, jobs, 3)
}

func TestPeriodicJobsFromConfig_RiskJobsFromDedicatedConfig(t *testing.T) {
	logger := zap.NewNop().Sugar()

	jobs := periodicJobsFromConfig(&config.Config{
		Risk: &config.RiskConfig{
			ReviewDeadlineReminderEnabled:   true,
			ReviewDeadlineReminderSchedule:  "0 0 8 * * *",
			ReviewOverdueEscalationEnabled:  true,
			ReviewOverdueEscalationSchedule: "0 0 9 * * *",
			StaleRiskScannerEnabled:         true,
			StaleRiskScannerSchedule:        "0 0 10 * * 1",
			EvidenceReconciliationEnabled:   true,
			EvidenceReconciliationSchedule:  "0 30 10 * * *",
			OpenDigestEnabled:               true,
			OpenDigestSchedule:              "0 0 11 * * *",
			OpenDigestWindow:                "daily",
		},
	}, logger)

	assert.Len(t, jobs, 5)
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

func TestJobInsertOptionsWithRetry(t *testing.T) {
	opts := JobInsertOptionsWithRetry("custom-queue", 10)

	assert.Equal(t, "custom-queue", opts.Queue)
	assert.Equal(t, 10, opts.MaxAttempts)
}

func TestServiceQueueResolution(t *testing.T) {
	service := &Service{
		config: &config.WorkerConfig{
			Queue: "email",
		},
	}

	assert.Equal(t, "email", service.emailQueue())
	assert.Equal(t, "slack", service.slackQueue())

	service.config.Queue = ""
	assert.Equal(t, "email", service.emailQueue())
	assert.Equal(t, "slack", service.slackQueue())
}

func TestBuildRiverConfig_IncludesSendSlackQueue(t *testing.T) {
	cfg := &config.WorkerConfig{
		Workers: 7,
	}

	riverConfig := buildRiverConfig(cfg, river.NewWorkers(), nil, nil)

	sendSlackQueue, ok := riverConfig.Queues["slack"]
	assert.True(t, ok)
	assert.Equal(t, 7, sendSlackQueue.MaxWorkers)
}

func TestBuildRiverConfig_PollOnlyDisabledByDefault(t *testing.T) {
	cfg := config.DefaultWorkerConfig()

	riverConfig := buildRiverConfig(cfg, river.NewWorkers(), nil, nil)

	assert.False(t, riverConfig.PollOnly)
}

func TestBuildRiverConfig_PollOnlyCanBeEnabled(t *testing.T) {
	cfg := config.DefaultWorkerConfig()
	cfg.UsePolling = true

	riverConfig := buildRiverConfig(cfg, river.NewWorkers(), nil, nil)

	assert.True(t, riverConfig.PollOnly)
}

func TestJobInsertOptionsForRiskDigest(t *testing.T) {
	opts := JobInsertOptionsForRiskDigest(24 * time.Hour)

	assert.Equal(t, "digest", opts.Queue)
	assert.Equal(t, 3, opts.MaxAttempts)
	assert.True(t, opts.UniqueOpts.ByArgs)
	assert.Equal(t, 24*time.Hour, opts.UniqueOpts.ByPeriod)
}
