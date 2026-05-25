package worker

import (
	"context"
	"fmt"
	"strings"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	notificationruntime "github.com/compliance-framework/api/internal/service/notification/runtime"
	"github.com/compliance-framework/api/internal/workflow"
)

const (
	defaultNotificationEmailQueue = "email"
	defaultNotificationSlackQueue = "slack"
	defaultNotificationMaxRetries = 5
)

type workerNotificationEmailSender struct {
	service EmailService
}

type workerNotificationEmailTemplateRenderer struct {
	service EmailService
}

type workerNotificationEnqueuer struct {
	client      workflow.RiverClient
	emailQueue  string
	maxAttempts int
}

func newWorkerNotificationRuntimeProvider(
	emailService EmailService,
	slackService SlackService,
	workerEnqueuerProvider notification.WorkerEnqueuerProvider,
) notification.RuntimeProvider {
	return notificationruntime.NewRegisteredRuntimeProvider(notificationruntime.ProviderRegistrations{
		EmailSender: func() emailprovider.Sender {
			if emailService == nil {
				return nil
			}
			return &workerNotificationEmailSender{service: emailService}
		},
		EmailEnqueuer: func() emailprovider.Enqueuer {
			if workerEnqueuerProvider == nil {
				return nil
			}

			workerEnqueuer := workerEnqueuerProvider()
			if workerEnqueuer == nil {
				return nil
			}

			enqueuer, ok := workerEnqueuer.(emailprovider.Enqueuer)
			if !ok {
				return nil
			}

			return enqueuer
		},
		EmailContentRenderer: func() emailprovider.ContentRenderer {
			if emailService == nil {
				return nil
			}
			return &workerNotificationEmailTemplateRenderer{service: emailService}
		},
		SlackSender: func() slackprovider.Sender {
			if slackService == nil {
				return nil
			}
			return slackService
		},
		SlackEnqueuer: func() slackprovider.Enqueuer {
			if workerEnqueuerProvider == nil {
				return nil
			}

			workerEnqueuer := workerEnqueuerProvider()
			if workerEnqueuer == nil {
				return nil
			}

			enqueuer, ok := workerEnqueuer.(slackprovider.Enqueuer)
			if !ok {
				return nil
			}

			return enqueuer
		},
	})
}

func newWorkerNotificationEnqueuer(client workflow.RiverClient, emailQueue string, maxAttempts int) notification.WorkerEnqueuer {
	return &workerNotificationEnqueuer{
		client:      client,
		emailQueue:  strings.TrimSpace(emailQueue),
		maxAttempts: normalizedNotificationMaxAttempts(maxAttempts),
	}
}

func (e *workerNotificationEnqueuer) IsStarted() bool {
	return e != nil && e.client != nil
}

func (e *workerNotificationEnqueuer) EnqueueNotificationEmail(ctx context.Context, delivery emailprovider.Delivery) ([]int64, error) {
	if e == nil || e.client == nil {
		return nil, fmt.Errorf("worker client is not initialized")
	}

	results, err := e.client.InsertMany(ctx, notificationEmailInsertParams(delivery, normalizedNotificationEmailQueue(e.emailQueue), e.maxAttempts))
	if err != nil {
		return nil, fmt.Errorf("failed to enqueue notification email delivery: %w", err)
	}

	return jobIDsFromInsertResults(results), nil
}

func (e *workerNotificationEnqueuer) EnqueueNotificationSlack(ctx context.Context, delivery slackprovider.Delivery) ([]int64, error) {
	if e == nil || e.client == nil {
		return nil, fmt.Errorf("worker client is not initialized")
	}

	params, err := notificationSlackInsertParams(delivery, defaultNotificationSlackQueue, e.maxAttempts)
	if err != nil {
		return nil, err
	}

	results, err := e.client.InsertMany(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to enqueue notification slack delivery: %w", err)
	}

	return jobIDsFromInsertResults(results), nil
}

func (s *workerNotificationEmailSender) IsEnabled() bool {
	return s != nil && s.service != nil
}

func (s *workerNotificationEmailSender) Send(ctx context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error) {
	if s == nil || s.service == nil {
		return nil, fmt.Errorf("email service is not configured")
	}
	return s.service.Send(ctx, message)
}

func (r *workerNotificationEmailTemplateRenderer) RenderTemplate(_ context.Context, content emailprovider.TemplateContent) (emailprovider.Content, error) {
	if r == nil || r.service == nil {
		return content.FallbackContent()
	}

	htmlBody, textBody, err := r.service.UseTemplate(content.TemplateName, content.TemplateData)
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render %s template: %w", content.TemplateName, err)
	}

	from := strings.TrimSpace(content.From)
	if from == "" {
		from = strings.TrimSpace(r.service.GetDefaultFromAddress())
	}

	return emailprovider.Content{
		From:        from,
		Subject:     strings.TrimSpace(content.Subject),
		HTMLBody:    htmlBody,
		TextBody:    textBody,
		Attachments: append([]emailtypes.Attachment(nil), content.Attachments...),
		Headers:     cloneNotificationEmailHeaders(content.Headers),
	}, nil
}

func cloneNotificationEmailHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}

func normalizedNotificationEmailQueue(queue string) string {
	trimmed := strings.TrimSpace(queue)
	if trimmed == "" {
		return defaultNotificationEmailQueue
	}
	return trimmed
}

func normalizedNotificationMaxAttempts(maxAttempts int) int {
	if maxAttempts <= 0 {
		return defaultNotificationMaxRetries
	}
	return maxAttempts
}
