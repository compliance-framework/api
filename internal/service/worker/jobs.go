package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
)

// Job types for email processing
const (
	JobTypeSendEmail        = "send_email"
	JobTypeSendEmailFrom    = "send_email_from"
	JobTypeSendGlobalDigest = "send_global_digest"
)

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
}

// Logger interface for logging
type Logger interface {
	Infow(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
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

// SendEmailWorker is a work function for sending emails
func SendEmailWorker(ctx context.Context, job *river.Job[SendEmailArgs]) error {
	// Get services from context (they should be injected by the worker service)
	emailService, ok := ctx.Value(emailServiceKey).(EmailService)
	if !ok {
		return fmt.Errorf("email service not found in job context")
	}

	logger, ok := ctx.Value(loggerKey).(Logger)
	if !ok {
		return fmt.Errorf("logger not found in job context")
	}

	args := job.Args

	logger.Infow("Processing send email job",
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
	result, err := emailService.Send(ctx, message)
	if err != nil {
		logger.Errorw("Failed to send email",
			"job_id", job.ID,
			"error", err,
		)
		return fmt.Errorf("failed to send email: %w", err)
	}

	if !result.Success {
		logger.Errorw("Email send failed",
			"job_id", job.ID,
			"error", result.Error,
		)
		return fmt.Errorf("email send failed: %s", result.Error)
	}

	logger.Infow("Email sent successfully",
		"job_id", job.ID,
		"message_id", result.MessageID,
	)

	return nil
}

// SendEmailFromWorker is a work function for sending emails from a provider
func SendEmailFromWorker(ctx context.Context, job *river.Job[SendEmailFromArgs]) error {
	// Get services from context (they should be injected by the worker service)
	emailService, ok := ctx.Value(emailServiceKey).(EmailService)
	if !ok {
		return fmt.Errorf("email service not found in job context")
	}

	logger, ok := ctx.Value(loggerKey).(Logger)
	if !ok {
		return fmt.Errorf("logger not found in job context")
	}

	args := job.Args

	logger.Infow("Processing send email from provider job",
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
	result, err := emailService.SendWithProvider(ctx, args.Provider, message)
	if err != nil {
		logger.Errorw("Failed to send email from provider",
			"job_id", job.ID,
			"provider", args.Provider,
			"error", err,
		)
		return fmt.Errorf("failed to send email from provider %s: %w", args.Provider, err)
	}

	if !result.Success {
		logger.Errorw("Email send failed from provider",
			"job_id", job.ID,
			"provider", args.Provider,
			"error", result.Error,
		)
		return fmt.Errorf("email send failed from provider %s: %s", args.Provider, result.Error)
	}

	logger.Infow("Email sent successfully from provider",
		"job_id", job.ID,
		"provider", args.Provider,
		"message_id", result.MessageID,
	)

	return nil
}

// SendGlobalDigestWorker is a work function for sending global digest
func SendGlobalDigestWorker(ctx context.Context, job *river.Job[SendGlobalDigestArgs]) error {
	// Get services from context
	digestService, ok := ctx.Value(digestServiceKey).(DigestService)
	if !ok {
		return fmt.Errorf("digest service not found in job context")
	}

	logger, ok := ctx.Value(loggerKey).(Logger)
	if !ok {
		return fmt.Errorf("logger not found in job context")
	}

	logger.Infow("Processing global digest job", "job_id", job.ID)

	// Send the global digest
	if err := digestService.SendGlobalDigest(ctx); err != nil {
		logger.Errorw("Failed to send global digest",
			"job_id", job.ID,
			"error", err,
		)
		return fmt.Errorf("failed to send global digest: %w", err)
	}

	logger.Infow("Global digest sent successfully", "job_id", job.ID)
	return nil
}

// JobInsertOptions returns common insert options for email jobs
func JobInsertOptions() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 5, // Retry up to 5 times
		// River uses exponential backoff by default
	}
}

// InsertSendEmailJob inserts a new send email job
func InsertSendEmailJob(ctx context.Context, client *river.Client[pgx.Tx], args *SendEmailArgs) error {
	_, err := client.Insert(ctx, args, JobInsertOptions())
	if err != nil {
		return fmt.Errorf("failed to insert send email job: %w", err)
	}

	return nil
}

// InsertSendEmailFromJob inserts a new send email from provider job
func InsertSendEmailFromJob(ctx context.Context, client *river.Client[pgx.Tx], args *SendEmailFromArgs) error {
	_, err := client.Insert(ctx, args, JobInsertOptions())
	if err != nil {
		return fmt.Errorf("failed to insert send email from job: %w", err)
	}

	return nil
}

// Workers returns all workers as work functions
func Workers() *river.Workers {
	workers := river.NewWorkers()
	river.AddWorker(workers, river.WorkFunc(SendEmailWorker))
	river.AddWorker(workers, river.WorkFunc(SendEmailFromWorker))
	river.AddWorker(workers, river.WorkFunc(SendGlobalDigestWorker))
	return workers
}
