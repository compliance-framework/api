package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Job types for email processing
const (
	JobTypeSendEmail        = "send_email"
	JobTypeSendEmailFrom    = "send_email_from"
	JobTypeSendGlobalDigest = "send_global_digest"
)

// Job types for workflow notifications
const (
	JobTypeWorkflowTaskAssigned    = "workflow_task_assigned"
	JobTypeWorkflowTaskDueSoon     = "workflow_task_due_soon"
	JobTypeWorkflowTaskDigest      = "workflow_task_digest"
	JobTypeWorkflowExecutionFailed = "workflow_execution_failed"
)

// Job types for risk processing
const (
	JobTypeRiskProcessEvidence = "risk_process_evidence"
)

// WorkflowTaskAssignedArgs represents the arguments for a new-task-assigned notification email
type WorkflowTaskAssignedArgs struct {
	AssignedToType        string     `json:"assigned_to_type"`
	UserID                string     `json:"user_id"`
	StepExecutionID       string     `json:"step_execution_id"`
	StepTitle             string     `json:"step_title"`
	WorkflowTitle         string     `json:"workflow_title"`
	WorkflowInstanceTitle string     `json:"workflow_instance_title"`
	StepURL               string     `json:"step_url"`
	DueDate               *time.Time `json:"due_date,omitempty"`
}

// WorkflowTaskDueSoonArgs represents the arguments for a task-due-in-1-day reminder email
type WorkflowTaskDueSoonArgs struct {
	UserID                string    `json:"user_id"`
	StepExecutionID       string    `json:"step_execution_id"`
	StepTitle             string    `json:"step_title"`
	WorkflowTitle         string    `json:"workflow_title"`
	WorkflowInstanceTitle string    `json:"workflow_instance_title"`
	StepURL               string    `json:"step_url"`
	DueDate               time.Time `json:"due_date"`
}

// WorkflowTaskDigestArgs represents the arguments for a per-user task digest email
type WorkflowTaskDigestArgs struct {
	UserID string `json:"user_id"`
}

// WorkflowExecutionFailedArgs represents the arguments for a workflow-execution-failed notification email
type WorkflowExecutionFailedArgs struct {
	WorkflowExecutionID string `json:"workflow_execution_id"`
}

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
func (WorkflowTaskAssignedArgs) Kind() string { return JobTypeWorkflowTaskAssigned }

// Kind returns the job kind for River
func (WorkflowTaskDueSoonArgs) Kind() string { return JobTypeWorkflowTaskDueSoon }

// Kind returns the job kind for River
func (WorkflowTaskDigestArgs) Kind() string { return JobTypeWorkflowTaskDigest }

// Kind returns the job kind for River
func (WorkflowExecutionFailedArgs) Kind() string { return JobTypeWorkflowExecutionFailed }

// Kind returns the job kind for River
func (RiskProcessEvidenceArgs) Kind() string { return JobTypeRiskProcessEvidence }

// Timeout returns the timeout for workflow task assigned jobs
func (WorkflowTaskAssignedArgs) Timeout() time.Duration { return 30 * time.Second }

// Timeout returns the timeout for workflow task due soon jobs
func (WorkflowTaskDueSoonArgs) Timeout() time.Duration { return 30 * time.Second }

// Timeout returns the timeout for workflow task digest jobs
func (WorkflowTaskDigestArgs) Timeout() time.Duration { return 5 * time.Minute }

// Timeout returns the timeout for workflow execution failed jobs
func (WorkflowExecutionFailedArgs) Timeout() time.Duration { return 30 * time.Second }

// Timeout returns the timeout for risk process evidence jobs
func (RiskProcessEvidenceArgs) Timeout() time.Duration { return 2 * time.Minute }

// SendEmailArgs represents the arguments for sending an email
type SendEmailArgs struct {
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

// SendGlobalDigestArgs represents the arguments for sending global digest
type SendGlobalDigestArgs struct {
	// No arguments needed - digest service will fetch data
}

// Kind returns the job kind for River
func (SendEmailArgs) Kind() string { return JobTypeSendEmail }

// Kind returns the job kind for River
func (SendEmailFromArgs) Kind() string { return JobTypeSendEmailFrom }

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
	ID                          string
	Email                       string
	FirstName                   string
	LastName                    string
	SlackUserID                 string
	NotificationSubscriptions   []NotificationSubscription
	TaskDailyDigestSubscribed   bool
	RiskNotificationsSubscribed bool
}

func (u NotificationUser) FullName() string {
	if u.LastName == "" {
		return u.FirstName
	}
	return u.FirstName + " " + u.LastName
}

func (u NotificationUser) NotificationChannels(notificationType string) []string {
	normalizedType, ok := notification.NormalizeNotificationType(notificationType)
	if !ok {
		return nil
	}

	seen := map[string]struct{}{}
	channels := make([]string, 0)
	for _, subscription := range u.NotificationSubscriptions {
		currentType, currentTypeOK := notification.NormalizeNotificationType(subscription.NotificationType)
		if !currentTypeOK || currentType != normalizedType {
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

// SendGlobalDigestWorker handles sending global digest jobs
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

// Work is the River work function for sending global digest
func (w *SendGlobalDigestWorker) Work(ctx context.Context, job *river.Job[SendGlobalDigestArgs]) error {
	w.logger.Infow("Processing global digest job", "job_id", job.ID)

	// Send the global digest
	if err := w.digestService.SendGlobalDigest(ctx); err != nil {
		w.logger.Errorw("Failed to send global digest",
			"job_id", job.ID,
			"error", err,
		)
		return fmt.Errorf("failed to send global digest: %w", err)
	}

	w.logger.Infow("Global digest sent successfully", "job_id", job.ID)
	return nil
}

// WorkflowTaskAssignedWorker handles new-task-assigned notification email jobs
type WorkflowTaskAssignedWorker struct {
	emailService EmailService
	slackService SlackService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

// NewWorkflowTaskAssignedWorker creates a new WorkflowTaskAssignedWorker
func NewWorkflowTaskAssignedWorker(emailService EmailService, slackService SlackService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *WorkflowTaskAssignedWorker {
	return &WorkflowTaskAssignedWorker{
		emailService: emailService,
		slackService: slackService,
		userRepo:     userRepo,
		webBaseURL:   webBaseURL,
		logger:       logger,
	}
}

// Work is the River work function for sending new-task-assigned notification emails
func (w *WorkflowTaskAssignedWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskAssignedArgs]) error {
	args := job.Args

	if args.AssignedToType == notification.DeliveryChannelEmail {
		return w.sendToEmailAddress(ctx, args)
	}
	return w.sendToUser(ctx, args)
}

// sendToUser looks up the user by ID and sends the notification if they are subscribed
func (w *WorkflowTaskAssignedWorker) sendToUser(ctx context.Context, args WorkflowTaskAssignedArgs) error {
	user, err := w.userRepo.FindUserByID(ctx, args.UserID)
	if err != nil {
		w.logger.Warnw("WorkflowTaskAssignedWorker: user not found, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return nil
	}

	channels := user.NotificationChannels(notification.NotificationTypeTaskAvailable)
	if len(channels) == 0 {
		w.logger.Debugw("WorkflowTaskAssignedWorker: user not subscribed, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
		)
		return nil
	}

	for _, channel := range channels {
		switch channel {
		case notification.DeliveryChannelEmail:
			if err := w.sendEmail(ctx, args, user.Email, user.FullName()); err != nil {
				return err
			}
		case notification.DeliveryChannelSlack:
			if err := w.sendSlack(ctx, args, user); err != nil {
				return err
			}
		default:
			w.logger.Debugw("WorkflowTaskAssignedWorker: unsupported channel, skipping",
				"step_execution_id", args.StepExecutionID,
				"user_id", args.UserID,
				"channel", channel,
			)
		}
	}

	return nil
}

func (w *WorkflowTaskAssignedWorker) sendSlack(ctx context.Context, args WorkflowTaskAssignedArgs, user NotificationUser) error {
	if w.slackService == nil || !w.slackService.IsEnabled() {
		w.logger.Debugw("WorkflowTaskAssignedWorker: slack service not configured, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
		)
		return nil
	}

	slackUserID := strings.TrimSpace(user.SlackUserID)
	if slackUserID == "" {
		w.logger.Debugw("WorkflowTaskAssignedWorker: user has no Slack link, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
		)
		return nil
	}

	message, err := slackformatters.FormatWorkflowTaskAssignedMessage(
		user.FullName(),
		args.StepTitle,
		args.WorkflowTitle,
		args.WorkflowInstanceTitle,
		resolveTaskURL(args.StepURL, w.webBaseURL),
		formatDueDate(args.DueDate),
	)
	if err != nil {
		return fmt.Errorf("failed to format workflow-task-assigned slack message: %w", err)
	}

	result, err := w.slackService.SendMessage(ctx, slackUserID, message)
	if err != nil {
		return fmt.Errorf("failed to send workflow-task-assigned slack message: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("workflow-task-assigned slack message send failed: %s", result.Error)
	}

	w.logger.Infow("WorkflowTaskAssignedWorker: slack message sent",
		"step_execution_id", args.StepExecutionID,
		"user_id", args.UserID,
		"slack_user_id", slackUserID,
		"delivery_id", result.DeliveryID,
	)

	return nil
}

// sendToEmailAddress sends the notification directly to the email address assignee without a user lookup
func (w *WorkflowTaskAssignedWorker) sendToEmailAddress(ctx context.Context, args WorkflowTaskAssignedArgs) error {
	return w.sendEmail(ctx, args, args.UserID, "")
}

// sendEmail renders the template and sends the notification email
func (w *WorkflowTaskAssignedWorker) sendEmail(ctx context.Context, args WorkflowTaskAssignedArgs, toAddress string, userName string) error {
	myTasksURL := resolveTaskURL(args.StepURL, w.webBaseURL)
	templateData := map[string]interface{}{
		"UserName":              userName,
		"StepTitle":             args.StepTitle,
		"WorkflowTitle":         args.WorkflowTitle,
		"WorkflowInstanceTitle": args.WorkflowInstanceTitle,
		"StepURL":               myTasksURL,
		"MyTasksURL":            w.webBaseURL + "/my-tasks",
		"DueDate":               formatDueDate(args.DueDate),
	}

	htmlBody, textBody, err := w.emailService.UseTemplate("workflow-task-assigned", templateData)
	if err != nil {
		w.logger.Errorw("WorkflowTaskAssignedWorker: failed to render template",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return fmt.Errorf("failed to render workflow-task-assigned template: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{toAddress},
		Subject:  fmt.Sprintf("Task ready for you: %s — %s", args.StepTitle, args.WorkflowTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		w.logger.Errorw("WorkflowTaskAssignedWorker: failed to send email",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return fmt.Errorf("failed to send workflow-task-assigned email: %w", err)
	}

	if !result.Success {
		w.logger.Errorw("WorkflowTaskAssignedWorker: email send reported failure",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", result.Error,
		)
		return fmt.Errorf("workflow-task-assigned email send failed: %s", result.Error)
	}

	w.logger.Infow("WorkflowTaskAssignedWorker: email sent",
		"step_execution_id", args.StepExecutionID,
		"user_id", args.UserID,
		"message_id", result.MessageID,
	)

	return nil
}

// WorkflowTaskDueSoonWorker handles task-due-soon reminder email jobs
type WorkflowTaskDueSoonWorker struct {
	emailService EmailService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

// NewWorkflowTaskDueSoonWorker creates a new WorkflowTaskDueSoonWorker
func NewWorkflowTaskDueSoonWorker(emailService EmailService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *WorkflowTaskDueSoonWorker {
	return &WorkflowTaskDueSoonWorker{
		emailService: emailService,
		userRepo:     userRepo,
		webBaseURL:   webBaseURL,
		logger:       logger,
	}
}

// Work is the River work function for sending task-due-in-1-day reminder emails
func (w *WorkflowTaskDueSoonWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskDueSoonArgs]) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.UserID)
	if err != nil {
		w.logger.Warnw("WorkflowTaskDueSoonWorker: user not found, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return nil
	}

	channels := user.NotificationChannels(notification.NotificationTypeTaskAvailable)
	if len(channels) == 0 {
		w.logger.Debugw("WorkflowTaskDueSoonWorker: user not subscribed, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
		)
		return nil
	}

	for _, channel := range channels {
		switch channel {
		case notification.DeliveryChannelEmail:
			if err := w.sendEmail(ctx, args, user); err != nil {
				return err
			}
		default:
			w.logger.Debugw("WorkflowTaskDueSoonWorker: unsupported channel, skipping",
				"step_execution_id", args.StepExecutionID,
				"user_id", args.UserID,
				"channel", channel,
			)
		}
	}

	return nil
}

func (w *WorkflowTaskDueSoonWorker) sendEmail(ctx context.Context, args WorkflowTaskDueSoonArgs, user NotificationUser) error {
	myTasksURL := resolveTaskURL(args.StepURL, w.webBaseURL)
	templateData := map[string]interface{}{
		"UserName":              user.FullName(),
		"StepTitle":             args.StepTitle,
		"WorkflowTitle":         args.WorkflowTitle,
		"WorkflowInstanceTitle": args.WorkflowInstanceTitle,
		"StepURL":               myTasksURL,
		"MyTasksURL":            w.webBaseURL + "/my-tasks",
		"DueDate":               formatDate(args.DueDate),
	}

	htmlBody, textBody, err := w.emailService.UseTemplate("workflow-task-due-soon", templateData)
	if err != nil {
		w.logger.Errorw("WorkflowTaskDueSoonWorker: failed to render template",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return fmt.Errorf("failed to render workflow-task-due-soon template: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{user.Email},
		Subject:  fmt.Sprintf("Reminder: %s is due soon — %s", args.StepTitle, args.WorkflowTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		w.logger.Errorw("WorkflowTaskDueSoonWorker: failed to send email",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return fmt.Errorf("failed to send workflow-task-due-soon email: %w", err)
	}

	if !result.Success {
		w.logger.Errorw("WorkflowTaskDueSoonWorker: email send reported failure",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", result.Error,
		)
		return fmt.Errorf("workflow-task-due-soon email send failed: %s", result.Error)
	}

	w.logger.Infow("WorkflowTaskDueSoonWorker: email sent",
		"step_execution_id", args.StepExecutionID,
		"user_id", args.UserID,
		"message_id", result.MessageID,
	)

	return nil
}

// JobInsertOptionsForWorkflowNotification returns insert options for workflow notification email jobs
func JobInsertOptionsForWorkflowNotification() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 5,
	}
}

func JobInsertOptionsForWorkflowTaskAssignedNotification() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 5 * time.Minute,
		},
	}
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
func Workers(emailService EmailService, digestService DigestService, slackService SlackService, userRepo UserRepository, db *gorm.DB, webBaseURL string, logger *zap.SugaredLogger) *river.Workers {
	workers := river.NewWorkers()

	// Create worker instances with dependencies
	sendEmailWorker := NewSendEmailWorker(emailService, logger)
	sendEmailFromWorker := NewSendEmailFromWorker(emailService, logger)
	// Register workers with their Work methods
	river.AddWorker(workers, river.WorkFunc(sendEmailWorker.Work))
	river.AddWorker(workers, river.WorkFunc(sendEmailFromWorker.Work))

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
		workflowTaskAssignedWorker := NewWorkflowTaskAssignedWorker(emailService, slackService, userRepo, webBaseURL, logger)
		river.AddWorker(workers, river.WorkFunc(workflowTaskAssignedWorker.Work))

		workflowTaskDueSoonWorker := NewWorkflowTaskDueSoonWorker(emailService, userRepo, webBaseURL, logger)
		river.AddWorker(workers, river.WorkFunc(workflowTaskDueSoonWorker.Work))

		if db != nil {
			workflowTaskDigestWorker := NewWorkflowTaskDigestWorker(db, emailService, userRepo, webBaseURL, logger)
			river.AddWorker(workers, river.WorkFunc(workflowTaskDigestWorker.Work))

			workflowExecutionFailedWorker := NewWorkflowExecutionFailedWorker(db, emailService, userRepo, webBaseURL, logger)
			river.AddWorker(workers, river.WorkFunc(workflowExecutionFailedWorker.Work))

			riskReviewDueReminderWorker := NewRiskReviewDueReminderWorker(db, emailService, userRepo, webBaseURL, logger)
			river.AddWorker(workers, river.WorkFunc(riskReviewDueReminderWorker.Work))

			riskReviewOverdueEscalationWorker := NewRiskReviewOverdueEscalationWorker(db, emailService, userRepo, webBaseURL, logger)
			river.AddWorker(workers, river.WorkFunc(riskReviewOverdueEscalationWorker.Work))

			riskStaleOpenReminderWorker := NewRiskStaleOpenReminderWorker(db, emailService, userRepo, webBaseURL, logger)
			river.AddWorker(workers, river.WorkFunc(riskStaleOpenReminderWorker.Work))

			riskOpenDigestWorker := NewRiskOpenDigestWorker(db, emailService, userRepo, webBaseURL, logger)
			river.AddWorker(workers, river.WorkFunc(riskOpenDigestWorker.Work))
		}
	}

	return workers
}
