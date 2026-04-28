package worker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Job types for email processing
const (
	JobTypeSendEmail        = "send_email"
	JobTypeSendEmailFrom    = "send_email_from"
	JobTypeSendSlackChannel = "send_channel"
	JobTypeSendSlackDM      = "send_dm"
	JobTypeSendGlobalDigest = "send_global_digest"
)

// Job types for risk processing
const (
	JobTypeRiskProcessEvidence = "risk_process_evidence"
)

// RiskProcessEvidenceArgs represents the arguments for processing evidence and creating risks.
// EvidenceEnd and Status are included alongside EvidenceID intentionally: River uses ByArgs uniqueness
// to deduplicate jobs within the 5-minute window. Including the end time and status ensures that two
// different evidence records for the same stream (different end times or states) each get their own
// independent deduplication window, preventing the second record from being silently dropped.
type RiskProcessEvidenceArgs struct {
	EvidenceID  uuid.UUID `json:"evidence_id"`
	EvidenceEnd string    `json:"evidence_end"`
	Status      string    `json:"status"`
}

// Kind returns the job kind for River
func (RiskProcessEvidenceArgs) Kind() string { return JobTypeRiskProcessEvidence }

// Timeout returns the timeout for risk process evidence jobs
func (RiskProcessEvidenceArgs) Timeout() time.Duration { return 2 * time.Minute }

// SendEmailArgs represents the arguments for sending an email
type SendEmailArgs struct {
	// Email message fields
	From        string             `json:"from"`
	To          []string           `json:"to" river:"unique"`
	Cc          []string           `json:"cc,omitempty"`
	Bcc         []string           `json:"bcc,omitempty"`
	Subject     string             `json:"subject"`
	HTMLBody    string             `json:"html_body,omitempty"`
	TextBody    string             `json:"text_body,omitempty"`
	Attachments []types.Attachment `json:"attachments,omitempty"`
	Headers     map[string]string  `json:"headers,omitempty"`

	// Optional notification metadata for generic notification dispatches.
	NotificationKind string `json:"notification_kind,omitempty"`
	RecipientUserID  string `json:"recipient_user_id,omitempty"`
	CorrelationID    string `json:"correlation_id,omitempty" river:"unique"`
	SourceJobKind    string `json:"source_job_kind,omitempty"`
	SourceJobID      string `json:"source_job_id,omitempty"`
}

// SendEmailFromArgs represents the arguments for sending an email from a specific provider
type SendEmailFromArgs struct {
	// Provider to use for sending
	Provider string `json:"provider"`

	// Email message fields
	From        string             `json:"from"`
	To          []string           `json:"to"`
	Cc          []string           `json:"cc,omitempty"`
	Bcc         []string           `json:"bcc,omitempty"`
	Subject     string             `json:"subject"`
	HTMLBody    string             `json:"html_body,omitempty"`
	TextBody    string             `json:"text_body,omitempty"`
	Attachments []types.Attachment `json:"attachments,omitempty"`
	Headers     map[string]string  `json:"headers,omitempty"`
}

// SendSlackArgs represents a Slack message before it is routed to a specific
// River job kind for channel or direct-message delivery.
type SendSlackArgs struct {
	Channel    string       `json:"channel" river:"unique"`
	TargetType string       `json:"target_type" river:"unique"`
	Text       string       `json:"text"`
	Blocks     slack.Blocks `json:"blocks,omitempty"`

	// Optional notification metadata for generic notification dispatches.
	NotificationKind string `json:"notification_kind,omitempty"`
	RecipientUserID  string `json:"recipient_user_id,omitempty"`
	CorrelationID    string `json:"correlation_id,omitempty" river:"unique"`
	SourceJobKind    string `json:"source_job_kind,omitempty"`
	SourceJobID      string `json:"source_job_id,omitempty"`
}

type SendSlackChannelArgs SendSlackArgs

type SendSlackDMArgs SendSlackArgs

// SendGlobalDigestArgs represents the arguments for sending global digest
type SendGlobalDigestArgs struct {
	// No arguments needed - digest service will fetch data
}

// Kind returns the job kind for River
func (SendEmailArgs) Kind() string { return JobTypeSendEmail }

// Kind returns the job kind for River
func (SendEmailFromArgs) Kind() string { return JobTypeSendEmailFrom }

// Kind returns the job kind for River
func (SendSlackChannelArgs) Kind() string { return JobTypeSendSlackChannel }

// Kind returns the job kind for River
func (SendSlackDMArgs) Kind() string { return JobTypeSendSlackDM }

// Kind returns the job kind for River
func (SendGlobalDigestArgs) Kind() string { return JobTypeSendGlobalDigest }

// EmailService interface for dependency injection
type EmailService interface {
	Send(ctx context.Context, message *types.Message) (*types.SendResult, error)
	SendWithProvider(ctx context.Context, providerName string, message *types.Message) (*types.SendResult, error)
	UseTemplate(templateName string, data map[string]interface{}) (htmlContent, textContent string, err error)
	GetDefaultFromAddress() string
}

type SlackService interface {
	SendMessage(ctx context.Context, channel string, message *slacktypes.Message) (*slacktypes.SendResult, error)
	IsEnabled() bool
}

// UserRepository is the minimal DB interface needed by notification workers
type UserRepository interface {
	FindUserByID(ctx context.Context, userID string) (NotificationUser, error)
}

// NotificationSubscription holds worker-facing notification subscription data.
type NotificationSubscription struct {
	NotificationType string
	Channels         []string
}

// NotificationUser holds the user fields needed for sending notification emails
type NotificationUser struct {
	ID                        string
	Email                     string
	FirstName                 string
	LastName                  string
	SlackUserID               string
	NotificationSubscriptions []NotificationSubscription
}

func (u NotificationUser) FullName() string {
	if u.LastName == "" {
		return u.FirstName
	}
	return u.FirstName + " " + u.LastName
}

func (u NotificationUser) NotificationChannels(subscriptionGate string) []string {
	normalizedGate, ok := notification.NormalizeSubscriptionGate(subscriptionGate)
	if !ok {
		return nil
	}

	seen := map[string]struct{}{}
	channels := make([]string, 0)
	for _, subscription := range u.NotificationSubscriptions {
		currentGate, currentGateOK := notification.NormalizeSubscriptionGate(subscription.NotificationType)
		if !currentGateOK || currentGate != normalizedGate {
			continue
		}

		for _, current := range subscription.Channels {
			channel, channelOK := notification.NormalizeDeliveryChannel(current)
			if !channelOK {
				continue
			}
			if _, ok := seen[channel]; ok {
				continue
			}
			seen[channel] = struct{}{}
			channels = append(channels, channel)
		}
	}

	return channels
}

func normalizeRequestedDeliveryChannel(channel string) (string, bool) {
	if strings.TrimSpace(channel) == "" {
		return "", true
	}
	return notification.NormalizeDeliveryChannel(channel)
}

func selectUserNotificationChannels(user NotificationUser, notificationType string, requestedChannel string) ([]string, bool) {
	channel, ok := normalizeRequestedDeliveryChannel(requestedChannel)
	if !ok {
		return nil, false
	}

	available := user.NotificationChannels(notificationType)
	if channel == "" {
		return available, true
	}
	if slices.Contains(available, channel) {
		return []string{channel}, true
	}

	return nil, true
}

// DigestService interface for dependency injection
type DigestService interface {
	SendGlobalDigest(ctx context.Context) error
}

// Timeout returns the timeout for email jobs
func (SendEmailArgs) Timeout() time.Duration {
	return 30 * time.Second
}

// Timeout returns the timeout for email jobs
func (SendEmailFromArgs) Timeout() time.Duration {
	return 30 * time.Second
}

// Timeout returns the timeout for slack channel jobs
func (SendSlackChannelArgs) Timeout() time.Duration {
	return 30 * time.Second
}

// Timeout returns the timeout for slack direct-message jobs
func (SendSlackDMArgs) Timeout() time.Duration {
	return 30 * time.Second
}

// Timeout returns the timeout for digest jobs (longer due to multiple emails)
func (SendGlobalDigestArgs) Timeout() time.Duration {
	return 5 * time.Minute
}

// SendEmailWorker handles sending email jobs
type SendEmailWorker struct {
	emailService EmailService
	logger       *zap.SugaredLogger
}

// NewSendEmailWorker creates a new SendEmailWorker
func NewSendEmailWorker(emailService EmailService, logger *zap.SugaredLogger) *SendEmailWorker {
	return &SendEmailWorker{
		emailService: emailService,
		logger:       logger,
	}
}

// Work is the River work function for sending emails
func (w *SendEmailWorker) Work(ctx context.Context, job *river.Job[SendEmailArgs]) error {
	args := job.Args

	// Validate required fields
	if len(args.To) == 0 {
		return fmt.Errorf("email job requires at least one recipient")
	}
	if strings.TrimSpace(args.Subject) == "" {
		return fmt.Errorf("email job requires a subject")
	}
	if strings.TrimSpace(args.HTMLBody) == "" && strings.TrimSpace(args.TextBody) == "" {
		return fmt.Errorf("email job requires either HTML body or text body")
	}

	w.logger.Infow("Processing send email job",
		"job_id", job.ID,
		"to", args.To,
		"subject", args.Subject,
	)

	// Convert args to email Message
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

	// Send the email
	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		w.logger.Errorw("Failed to send email",
			"job_id", job.ID,
			"error", err,
		)
		return fmt.Errorf("failed to send email: %w", err)
	}

	if !result.Success {
		w.logger.Errorw("Email send failed",
			"job_id", job.ID,
			"error", result.Error,
		)
		return fmt.Errorf("email send failed: %s", result.Error)
	}

	w.logger.Infow("Email sent successfully",
		"job_id", job.ID,
		"message_id", result.MessageID,
	)

	return nil
}

// SendEmailFromWorker handles sending email from provider jobs
type SendEmailFromWorker struct {
	emailService EmailService
	logger       *zap.SugaredLogger
}

// SendSlackWorker handles sending Slack message jobs.
type SendSlackWorker struct {
	slackService SlackService
	logger       *zap.SugaredLogger
}

// NewSendEmailFromWorker creates a new SendEmailFromWorker
func NewSendEmailFromWorker(emailService EmailService, logger *zap.SugaredLogger) *SendEmailFromWorker {
	return &SendEmailFromWorker{
		emailService: emailService,
		logger:       logger,
	}
}

// Work is the River work function for sending emails from a provider
func (w *SendEmailFromWorker) Work(ctx context.Context, job *river.Job[SendEmailFromArgs]) error {
	args := job.Args

	// Validate required fields
	if strings.TrimSpace(args.Provider) == "" {
		return fmt.Errorf("email from provider job requires a provider name")
	}
	if len(args.To) == 0 {
		return fmt.Errorf("email job requires at least one recipient")
	}
	if strings.TrimSpace(args.Subject) == "" {
		return fmt.Errorf("email job requires a subject")
	}
	if strings.TrimSpace(args.HTMLBody) == "" && strings.TrimSpace(args.TextBody) == "" {
		return fmt.Errorf("email job requires either HTML body or text body")
	}

	w.logger.Infow("Processing send email from provider job",
		"job_id", job.ID,
		"provider", args.Provider,
		"to", args.To,
		"subject", args.Subject,
	)

	// Convert args to email Message
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

	// Send the email using the specified provider
	result, err := w.emailService.SendWithProvider(ctx, args.Provider, message)
	if err != nil {
		w.logger.Errorw("Failed to send email from provider",
			"job_id", job.ID,
			"provider", args.Provider,
			"error", err,
		)
		return fmt.Errorf("failed to send email from provider %s: %w", args.Provider, err)
	}

	if !result.Success {
		w.logger.Errorw("Email send failed from provider",
			"job_id", job.ID,
			"provider", args.Provider,
			"error", result.Error,
		)
		return fmt.Errorf("email send failed from provider %s: %s", args.Provider, result.Error)
	}

	w.logger.Infow("Email sent successfully from provider",
		"job_id", job.ID,
		"provider", args.Provider,
		"message_id", result.MessageID,
	)

	return nil
}

// NewSendSlackWorker creates a new SendSlackWorker.
func NewSendSlackWorker(slackService SlackService, logger *zap.SugaredLogger) *SendSlackWorker {
	return &SendSlackWorker{
		slackService: slackService,
		logger:       logger,
	}
}

func cloneSlackArgs(args SendSlackArgs) SendSlackArgs {
	return SendSlackArgs{
		Channel:          strings.TrimSpace(args.Channel),
		TargetType:       strings.TrimSpace(args.TargetType),
		Text:             args.Text,
		NotificationKind: strings.TrimSpace(args.NotificationKind),
		RecipientUserID:  strings.TrimSpace(args.RecipientUserID),
		CorrelationID:    strings.TrimSpace(args.CorrelationID),
		SourceJobKind:    strings.TrimSpace(args.SourceJobKind),
		SourceJobID:      strings.TrimSpace(args.SourceJobID),
		Blocks: slack.Blocks{
			BlockSet: append([]slack.Block(nil), args.Blocks.BlockSet...),
		},
	}
}

func selectSlackJobArgs(args SendSlackArgs) (river.JobArgs, error) {
	cloned := cloneSlackArgs(args)
	targetType, ok := slackprovider.NormalizeTargetType(cloned.TargetType)
	if !ok {
		return nil, fmt.Errorf("send slack job requires a supported target type")
	}
	cloned.TargetType = targetType

	switch targetType {
	case slackprovider.TargetTypeDirectMessage:
		return SendSlackDMArgs(cloned), nil
	case slackprovider.TargetTypeChannel:
		return SendSlackChannelArgs(cloned), nil
	default:
		return nil, fmt.Errorf("unsupported slack target type %q", cloned.TargetType)
	}
}

func riverJobID[T river.JobArgs](job *river.Job[T]) int64 {
	if job == nil || job.JobRow == nil {
		return 0
	}

	return job.ID
}

// WorkChannel is the River work function for sending Slack channel messages.
func (w *SendSlackWorker) WorkChannel(ctx context.Context, job *river.Job[SendSlackChannelArgs]) error {
	return w.send(ctx, riverJobID(job), JobTypeSendSlackChannel, cloneSlackArgs(SendSlackArgs(job.Args)))
}

// WorkDM is the River work function for sending Slack direct messages.
func (w *SendSlackWorker) WorkDM(ctx context.Context, job *river.Job[SendSlackDMArgs]) error {
	return w.send(ctx, riverJobID(job), JobTypeSendSlackDM, cloneSlackArgs(SendSlackArgs(job.Args)))
}

func (w *SendSlackWorker) send(ctx context.Context, jobID int64, jobKind string, args SendSlackArgs) error {
	if strings.TrimSpace(args.Channel) == "" {
		return fmt.Errorf("slack job requires a channel")
	}
	if strings.TrimSpace(args.Text) == "" && len(args.Blocks.BlockSet) == 0 {
		return fmt.Errorf("slack job requires text or blocks")
	}
	if w.slackService == nil || !w.slackService.IsEnabled() {
		w.logger.Debugw("SendSlackWorker: slack service not configured, skipping",
			"job_id", jobID,
			"job_kind", jobKind,
			"channel", args.Channel,
		)
		return nil
	}

	message := &slacktypes.Message{
		Text:   args.Text,
		Blocks: append([]slack.Block(nil), args.Blocks.BlockSet...),
	}

	w.logger.Infow("Processing send slack job",
		"job_id", jobID,
		"job_kind", jobKind,
		"channel", args.Channel,
	)

	result, err := w.slackService.SendMessage(ctx, args.Channel, message)
	if err != nil {
		w.logger.Errorw("Failed to send slack message",
			"job_id", jobID,
			"job_kind", jobKind,
			"channel", args.Channel,
			"error", err,
		)
		return fmt.Errorf("failed to send slack message: %w", err)
	}
	if !result.Success {
		w.logger.Errorw("Slack message send failed",
			"job_id", jobID,
			"job_kind", jobKind,
			"channel", args.Channel,
			"error", result.Error,
		)
		return fmt.Errorf("slack message send failed: %s", result.Error)
	}

	w.logger.Infow("Slack message sent successfully",
		"job_id", jobID,
		"job_kind", jobKind,
		"channel", result.Channel,
		"delivery_id", result.DeliveryID,
	)

	return nil
}

// SendGlobalDigestWorker handles scheduling global digest deliveries.
type SendGlobalDigestWorker struct {
	digestService DigestService
	logger        *zap.SugaredLogger
}

// NewSendGlobalDigestWorker creates a new SendGlobalDigestWorker
func NewSendGlobalDigestWorker(digestService DigestService, logger *zap.SugaredLogger) *SendGlobalDigestWorker {
	return &SendGlobalDigestWorker{
		digestService: digestService,
		logger:        logger,
	}
}

// Work is the River work function for scheduling global digest deliveries.
func (w *SendGlobalDigestWorker) Work(ctx context.Context, job *river.Job[SendGlobalDigestArgs]) error {
	w.logger.Infow("Processing global digest job", "job_id", job.ID)

	if err := w.digestService.SendGlobalDigest(ctx); err != nil {
		w.logger.Errorw("Failed to send global digest",
			"job_id", job.ID,
			"error", err,
		)
		return fmt.Errorf("failed to send global digest: %w", err)
	}

	w.logger.Infow("Global digest processed successfully", "job_id", job.ID)
	return nil
}

// JobInsertOptionsForRiskProcessEvidence returns insert options for risk processing jobs
func JobInsertOptionsForRiskProcessEvidence() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "risk",
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 5 * time.Minute,
		},
	}
}

// JobInsertOptionsWithRetry returns insert options for jobs with custom retry policy
func JobInsertOptionsWithRetry(queue string, maxAttempts int) *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       queue,
		MaxAttempts: maxAttempts,
	}
}

// Workers returns all workers as work functions with dependencies injected
func Workers(
	emailService EmailService,
	digestService DigestService,
	slackService SlackService,
	userRepo UserRepository,
	db *gorm.DB,
	webBaseURL string,
	notificationWorkerEnqueuer notification.WorkerEnqueuer,
	logger *zap.SugaredLogger,
) *river.Workers {
	workers := river.NewWorkers()

	// Create worker instances with dependencies
	sendEmailWorker := NewSendEmailWorker(emailService, logger)
	sendEmailFromWorker := NewSendEmailFromWorker(emailService, logger)
	sendSlackWorker := NewSendSlackWorker(slackService, logger)
	// Register workers with their Work methods
	river.AddWorker(workers, river.WorkFunc(sendEmailWorker.Work))
	river.AddWorker(workers, river.WorkFunc(sendEmailFromWorker.Work))
	river.AddWorker(workers, river.WorkFunc(sendSlackWorker.WorkChannel))
	river.AddWorker(workers, river.WorkFunc(sendSlackWorker.WorkDM))

	// Only create and register the global digest worker if the digest service is available
	if digestService != nil {
		sendGlobalDigestWorker := NewSendGlobalDigestWorker(digestService, logger)
		river.AddWorker(workers, river.WorkFunc(sendGlobalDigestWorker.Work))
	}

	// Register risk evidence worker — requires only db, independent of email/userRepo config.
	if db != nil {
		riskEvidenceWorker := NewRiskEvidenceWorker(db, logger)
		river.AddWorker(workers, river.WorkFunc(riskEvidenceWorker.Work))

		riskReconcileDuplicatesWorker := NewRiskReconcileDuplicatesWorker(db, logger)
		river.AddWorker(workers, river.WorkFunc(riskReconcileDuplicatesWorker.Work))

		riskReviewOverdueReopenWorker := NewRiskReviewOverdueReopenWorker(db, logger)
		river.AddWorker(workers, river.WorkFunc(riskReviewOverdueReopenWorker.Work))
	}

	// Register workflow notification workers if dependencies are available
	if userRepo != nil {
		workflowAssignedRuntimeProvider := newWorkerNotificationRuntimeProvider(
			emailService,
			slackService,
			func() notification.WorkerEnqueuer { return notificationWorkerEnqueuer },
		)
		sharedNotificationRuntimeProvider := newWorkerNotificationRuntimeProvider(
			emailService,
			slackService,
			func() notification.WorkerEnqueuer { return notificationWorkerEnqueuer },
		)

		workflowTaskAssignedWorker := NewWorkflowTaskAssignedWorker(
			userRepo,
			webBaseURL,
			workflowAssignedRuntimeProvider,
			logger,
		)
		workflowTaskAssignedWorker.db = db
		river.AddWorker(workers, river.WorkFunc(workflowTaskAssignedWorker.Work))

		workflowTaskDueSoonWorker := NewWorkflowTaskDueSoonWorker(
			userRepo,
			webBaseURL,
			sharedNotificationRuntimeProvider,
			logger,
		)
		river.AddWorker(workers, river.WorkFunc(workflowTaskDueSoonWorker.Work))

		if db != nil {
			riskNotificationServiceFactory := NewRiskNotificationServiceFactory(sharedNotificationRuntimeProvider)
			workflowTaskDigestWorker := NewWorkflowTaskDigestWorker(
				db,
				userRepo,
				webBaseURL,
				sharedNotificationRuntimeProvider,
				logger,
			)
			river.AddWorker(workers, river.WorkFunc(workflowTaskDigestWorker.Work))

			workflowExecutionFailedWorker := NewWorkflowExecutionFailedWorker(
				db,
				userRepo,
				webBaseURL,
				sharedNotificationRuntimeProvider,
				logger,
			)
			river.AddWorker(workers, river.WorkFunc(workflowExecutionFailedWorker.Work))

			poamNotificationServiceFactory := NewPoamNotificationServiceFactory(sharedNotificationRuntimeProvider)

			riskReviewDueReminderWorker := NewRiskReviewDueReminderWorker(db, userRepo, webBaseURL, riskNotificationServiceFactory, logger)
			river.AddWorker(workers, river.WorkFunc(riskReviewDueReminderWorker.Work))

			riskReviewOverdueEscalationWorker := NewRiskReviewOverdueEscalationWorker(db, userRepo, webBaseURL, riskNotificationServiceFactory, logger)
			river.AddWorker(workers, river.WorkFunc(riskReviewOverdueEscalationWorker.Work))

			riskStaleOpenReminderWorker := NewRiskStaleOpenReminderWorker(db, userRepo, webBaseURL, riskNotificationServiceFactory, logger)
			river.AddWorker(workers, river.WorkFunc(riskStaleOpenReminderWorker.Work))

			riskOpenDigestWorker := NewRiskOpenDigestWorker(db, userRepo, webBaseURL, riskNotificationServiceFactory, logger)
			river.AddWorker(workers, river.WorkFunc(riskOpenDigestWorker.Work))

			// Register POAM notification workers (BCH-1186 Phase 3)
			poamDeadlineReminderWorker := NewPoamDeadlineReminderWorker(
				userRepo,
				webBaseURL,
				poamNotificationServiceFactory,
				logger,
			)
			river.AddWorker(workers, river.WorkFunc(poamDeadlineReminderWorker.Work))

			poamOverdueNotificationWorker := NewPoamOverdueNotificationWorker(
				userRepo,
				webBaseURL,
				poamNotificationServiceFactory,
				logger,
			)
			river.AddWorker(workers, river.WorkFunc(poamOverdueNotificationWorker.Work))

			milestoneOverdueReminderWorker := NewMilestoneOverdueReminderWorker(
				userRepo,
				webBaseURL,
				poamNotificationServiceFactory,
				logger,
			)
			river.AddWorker(workers, river.WorkFunc(milestoneOverdueReminderWorker.Work))

			// Register POAM digest worker (BCH-1186 Phase 4)
			// Note: PoamOpenDigestSchedulerWorker is registered in service.go (needs clientProxy).
			poamOpenDigestWorker := NewPoamOpenDigestWorker(
				db,
				userRepo,
				webBaseURL,
				poamNotificationServiceFactory,
				logger,
			)
			river.AddWorker(workers, river.WorkFunc(poamOpenDigestWorker.Work))
		}
	}

	return workers
}
