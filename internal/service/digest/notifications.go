package digest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	"github.com/slack-go/slack"
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

func (m evidenceDigestNotificationModel) slackSummary() *slackformatters.DigestSummary {
	summary := m.summary()
	return &slackformatters.DigestSummary{
		TotalCount:        summary.TotalCount,
		SatisfiedCount:    summary.SatisfiedCount,
		NotSatisfiedCount: summary.NotSatisfiedCount,
		ExpiredCount:      summary.ExpiredCount,
		TopExpired:        toSlackDigestEvidence(summary.TopExpired),
		TopNotSatisfied:   toSlackDigestEvidence(summary.TopNotSatisfied),
		BaseURL:           m.WebBaseURL,
	}
}

func (m evidenceDigestNotificationModel) summary() *EvidenceSummary {
	if m.Summary == nil {
		return &EvidenceSummary{}
	}
	return m.Summary
}

func (s *Service) evidenceDigestDefinition() notification.Definition {
	return notification.Definition{
		Kind:              evidenceDigestKind,
		SubscriptionType:  notification.NotificationTypeEvidenceDigest,
		SupportedChannels: []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: notification.EmailChannelRenderer(s.renderEvidenceDigestEmail),
			notification.DeliveryChannelSlack: notification.SlackChannelRenderer(s.renderEvidenceDigestSlack),
		},
	}
}

func (s *Service) newNotificationService() *notification.Service {
	runtime := notification.MustNewRuntime(
		notification.NewDeliveryTransport(
			notification.WithWorkerEnqueuerProvider(func() notification.WorkerEnqueuer {
				return s.workerService
			}),
			notification.WithEmailSenderProvider(func() notification.EmailSender {
				if s.emailService == nil {
					return nil
				}
				return s.emailService
			}),
			notification.WithSlackSenderProvider(func() notification.SlackSender {
				if s.slackService == nil {
					return nil
				}
				return s.slackService
			}),
		),
		notification.NewGORMUserRepository(s.db),
		notification.NewConfigDestinationResolver(s.config),
		notification.WithDefaultEmailFrom(s.getDefaultFromAddress()),
	)

	runtime.MustRegister(s.evidenceDigestDefinition())

	return runtime.Service()
}

func (s *Service) renderEvidenceDigestEmail(_ context.Context, model any) (notification.EmailContent, error) {
	if s.emailService == nil {
		return notification.EmailContent{}, fmt.Errorf("email service is not configured")
	}

	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return notification.EmailContent{}, err
	}

	htmlContent, textContent, err := s.emailService.UseTemplate("evidence-digest", digestModel.templateData())
	if err != nil {
		return notification.EmailContent{}, fmt.Errorf("failed to render digest template: %w", err)
	}

	return notification.EmailContent{
		Subject:  "Evidence Compliance Digest",
		HTMLBody: htmlContent,
		TextBody: textContent,
	}, nil
}

func (s *Service) renderEvidenceDigestSlack(_ context.Context, model any) (notification.SlackContent, error) {
	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return notification.SlackContent{}, err
	}

	message, err := slackformatters.FormatDigestMessage(digestModel.slackSummary())
	if err != nil {
		return notification.SlackContent{}, fmt.Errorf("failed to format slack message for digest: %w", err)
	}

	return notification.SlackContent{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
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
					Key: notification.ConfiguredDestinationSlackDigestChannel,
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
