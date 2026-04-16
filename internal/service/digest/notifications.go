package digest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"gorm.io/gorm"
)

const evidenceDigestKind = notification.Kind(notification.NotificationTypeEvidenceDigest)

type evidenceDigestNotificationModel struct {
	UserName    string
	GeneratedAt string
	WebBaseURL  string
	Summary     *EvidenceSummary
}

func newEvidenceDigestNotificationModel(summary *EvidenceSummary, userName, webBaseURL string, generatedAt time.Time) evidenceDigestNotificationModel {
	return evidenceDigestNotificationModel{
		UserName:    strings.TrimSpace(userName),
		GeneratedAt: generatedAt.UTC().Format(time.RFC1123),
		WebBaseURL:  strings.TrimSpace(webBaseURL),
		Summary:     summary,
	}
}

func (m evidenceDigestNotificationModel) templateData() map[string]interface{} {
	summary := m.summary()

	return map[string]interface{}{
		"UserName":          m.UserName,
		"TotalCount":        summary.TotalCount,
		"SatisfiedCount":    summary.SatisfiedCount,
		"NotSatisfiedCount": summary.NotSatisfiedCount,
		"ExpiredCount":      summary.ExpiredCount,
		"TopExpired":        summary.TopExpired,
		"TopNotSatisfied":   summary.TopNotSatisfied,
		"WebBaseURL":        m.WebBaseURL,
		"GeneratedAt":       m.GeneratedAt,
	}
}

func (m evidenceDigestNotificationModel) summary() *EvidenceSummary {
	if m.Summary == nil {
		return &EvidenceSummary{}
	}
	return m.Summary
}

func evidenceDigestDefinition(emailService *email.Service) notification.Definition {
	return notification.Definition{
		Kind:              evidenceDigestKind,
		SubscriptionType:  notification.NotificationTypeEvidenceDigest,
		SupportedChannels: []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: emailprovider.Renderer(func(ctx context.Context, model any) (emailprovider.Content, error) {
				return renderEvidenceDigestEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderEvidenceDigestSlack(ctx, model)
			}),
		},
	}
}

type digestSlackEnqueuer interface {
	IsStarted() bool
	EnqueueNotificationSlack(ctx context.Context, delivery slackprovider.Delivery) error
}

func NewNotificationService(
	db *gorm.DB,
	emailService *email.Service,
	cfg *config.Config,
	runtimeProvider notification.RuntimeProvider,
) *notification.Service {
	if db == nil || runtimeProvider == nil {
		return notification.NewService(nil, nil, nil)
	}

	return runtimeProvider.NewRuntimeFactory(newDigestConfiguredDestinationResolver(cfg)).MustNewService(
		notification.NewGORMUserRepository(db),
		evidenceDigestDefinition(emailService),
	)
}

func NewRuntimeProvider(
	emailService *email.Service,
	cfg *config.Config,
	workerEnqueuerProvider notification.WorkerEnqueuerProvider,
	slackSenderProvider slackprovider.SenderProvider,
) notification.RuntimeProvider {
	if workerEnqueuerProvider == nil {
		workerEnqueuerProvider = func() notification.WorkerEnqueuer { return nil }
	}
	if slackSenderProvider == nil {
		slackSenderProvider = func() slackprovider.Sender { return nil }
	}

	transport := notification.NewDeliveryTransport(
		notification.WithProvider(emailprovider.NewProvider(
			func() emailprovider.Sender {
				if emailService == nil {
					return nil
				}
				return emailService
			},
			func() emailprovider.Enqueuer {
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
		)),
		notification.WithProvider(slackprovider.NewProvider(
			slackSenderProvider,
			func() slackprovider.Enqueuer {
				workerEnqueuer := workerEnqueuerProvider()
				if workerEnqueuer == nil {
					return nil
				}

				enqueuer, ok := workerEnqueuer.(digestSlackEnqueuer)
				if !ok {
					return nil
				}

				return enqueuer
			},
		)),
	)

	return notification.NewStaticRuntimeProvider(transport)
}

type digestConfiguredDestinationResolver struct {
	config *config.Config
}

func newDigestConfiguredDestinationResolver(cfg *config.Config) digestConfiguredDestinationResolver {
	return digestConfiguredDestinationResolver{config: cfg}
}

func (r digestConfiguredDestinationResolver) ResolveConfiguredDestination(_ context.Context, key string) (notification.ConfiguredDestination, error) {
	if strings.TrimSpace(key) != slackprovider.ConfiguredDestinationDigestChan {
		return notification.ConfiguredDestination{}, fmt.Errorf("%w: %q", notification.ErrConfiguredDestinationNotFound, key)
	}
	if r.config == nil || r.config.Slack == nil || !r.config.Slack.Enabled {
		return notification.ConfiguredDestination{}, fmt.Errorf("%w: %q", notification.ErrConfiguredDestinationNotFound, key)
	}

	channel := strings.TrimSpace(r.config.Slack.DigestChannel)
	if channel == "" {
		return notification.ConfiguredDestination{}, fmt.Errorf("%w: %q", notification.ErrConfiguredDestinationNotFound, key)
	}

	return notification.ConfiguredDestination{
		Provider: notification.DeliveryChannelSlack,
		Address: map[string]string{
			slackprovider.AddressKeyChannel:    channel,
			slackprovider.AddressKeyTargetType: slackprovider.TargetTypeChannel,
		},
	}, nil
}

func renderEvidenceDigestEmail(_ context.Context, emailService *email.Service, model any) (emailprovider.Content, error) {
	if emailService == nil {
		return emailprovider.Content{}, fmt.Errorf("email service is not configured")
	}

	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return emailprovider.Content{}, err
	}

	htmlContent, textContent, err := emailService.UseTemplate("evidence-digest", digestModel.templateData())
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render digest template: %w", err)
	}

	return emailprovider.Content{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  "Evidence Compliance Digest",
		HTMLBody: htmlContent,
		TextBody: textContent,
	}, nil
}

func evidenceDigestModelFromAny(model any) (evidenceDigestNotificationModel, error) {
	switch typed := model.(type) {
	case evidenceDigestNotificationModel:
		return typed, nil
	case *evidenceDigestNotificationModel:
		if typed == nil {
			return evidenceDigestNotificationModel{}, fmt.Errorf("evidence digest model is required")
		}
		return *typed, nil
	default:
		return evidenceDigestNotificationModel{}, fmt.Errorf("unexpected evidence digest model type %T", model)
	}
}

func (s *Service) dispatchEvidenceDigestNotifications(
	ctx context.Context,
	summary *EvidenceSummary,
	webBaseURL string,
	generatedAt time.Time,
	includeConfiguredSlack bool,
	includeSubscribedUsers bool,
) error {
	request := notification.FanoutRequest{}
	dispatchOptions := evidenceDigestDispatchOptions(generatedAt)

	if includeConfiguredSlack {
		request.Requests = append(request.Requests, notification.Request{
			Kind: evidenceDigestKind,
			Audiences: []notification.Audience{
				{ConfiguredDestination: &notification.ConfiguredDestinationAudience{
					Key: slackprovider.ConfiguredDestinationDigestChan,
				}},
			},
			Model:   newEvidenceDigestNotificationModel(summary, "", webBaseURL, generatedAt),
			Options: dispatchOptions,
		})
	}

	if includeSubscribedUsers {
		request.SubscribedUsers = append(request.SubscribedUsers, notification.SubscribedUsersRequest{
			Kind:    evidenceDigestKind,
			Options: dispatchOptions,
			BuildModel: func(_ context.Context, user notification.User) (any, error) {
				return newEvidenceDigestNotificationModel(summary, user.FirstName, webBaseURL, generatedAt), nil
			},
		})
	}

	if len(request.Requests) == 0 && len(request.SubscribedUsers) == 0 {
		return nil
	}

	return s.notifier.DispatchFanout(ctx, request)
}

func evidenceDigestDispatchOptions(generatedAt time.Time) notification.DispatchOptions {
	correlationID := fmt.Sprintf("evidence-digest:%s", generatedAt.UTC().Format(time.RFC3339Nano))

	return notification.DispatchOptions{
		CorrelationID: correlationID,
		SourceJobKind: "send_global_digest",
	}
}

func (s *Service) globalDigestSlackEnabled() bool {
	if s.config == nil || s.config.Slack == nil || !s.config.Slack.Enabled {
		return false
	}
	if strings.TrimSpace(s.config.Slack.DigestChannel) == "" {
		s.logger.Debug("Slack digest channel is empty; skipping optional digest Slack message")
		return false
	}
	return true
}
