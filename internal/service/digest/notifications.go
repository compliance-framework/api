package digest

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"gorm.io/gorm"
)

const evidenceDigestKind = notification.Kind("evidence_digest")

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

type digestNotificationEmailTemplateRenderer struct {
	emailService *email.Service
}

func NewEmailTemplateRendererProvider(emailService *email.Service) emailprovider.ContentRendererProvider {
	return func() emailprovider.ContentRenderer {
		return newDigestNotificationEmailTemplateRenderer(emailService)
	}
}

func newDigestNotificationEmailTemplateRenderer(emailService *email.Service) emailprovider.ContentRenderer {
	if emailService == nil {
		return nil
	}
	return &digestNotificationEmailTemplateRenderer{emailService: emailService}
}

func renderEvidenceDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "evidence-digest",
		TemplateData: digestModel.templateData(),
		Subject:      "Evidence Compliance Digest",
		TextBody:     "Evidence compliance digest is ready.",
	}, nil
}

func (r *digestNotificationEmailTemplateRenderer) RenderTemplate(_ context.Context, content emailprovider.TemplateContent) (emailprovider.Content, error) {
	if r == nil || r.emailService == nil {
		return content.FallbackContent()
	}

	htmlContent, textContent, err := r.emailService.UseTemplate(content.TemplateName, content.TemplateData)
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render %s template: %w", content.TemplateName, err)
	}

	from := strings.TrimSpace(content.From)
	if from == "" {
		from = strings.TrimSpace(r.emailService.GetDefaultFromAddress())
	}

	return emailprovider.Content{
		From:        from,
		Subject:     strings.TrimSpace(content.Subject),
		HTMLBody:    htmlContent,
		TextBody:    textContent,
		Attachments: append([]emailtypes.Attachment(nil), content.Attachments...),
		Headers:     cloneDigestNotificationEmailHeaders(content.Headers),
	}, nil
}

func cloneDigestNotificationEmailHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}

	return cloned
}

func NewNotificationService(
	db *gorm.DB,
	cfg *config.Config,
	notificationRuntime notification.RuntimeProvider,
) *notification.Service {
	if db == nil || notificationRuntime == nil {
		return notification.NewService(nil, nil, nil)
	}

	return notificationRuntime.NewRuntimeFactory(notification.NewGORMConfiguredDestinationResolver(db)).MustNewService(
		notification.NewGORMUserRepository(db),
		notification.NewDefinition(
			evidenceDigestKind,
			notification.SubscriptionGateEvidenceDigest,
			emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
				return renderEvidenceDigestEmail(ctx, model)
			}),
			slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
				return renderEvidenceDigestSlack(ctx, model)
			}),
		),
	)
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

func (m evidenceDigestNotificationModel) slackSummary() *slackprovider.DigestSummary {
	summary := m.summary()
	return &slackprovider.DigestSummary{
		TotalCount:        summary.TotalCount,
		SatisfiedCount:    summary.SatisfiedCount,
		NotSatisfiedCount: summary.NotSatisfiedCount,
		ExpiredCount:      summary.ExpiredCount,
		TopExpired:        toSlackDigestEvidence(summary.TopExpired),
		TopNotSatisfied:   toSlackDigestEvidence(summary.TopNotSatisfied),
		BaseURL:           m.WebBaseURL,
	}
}

func toSlackDigestEvidence(items []EvidenceItem) []slackprovider.DigestSummaryEvidence {
	if len(items) == 0 {
		return nil
	}

	out := make([]slackprovider.DigestSummaryEvidence, 0, len(items))
	for i := range items {
		out = append(out, slackprovider.DigestSummaryEvidence{
			ID:          items[i].ID,
			Title:       items[i].Title,
			Description: items[i].Description,
			ExpiresAt:   items[i].ExpiresAt,
		})
	}

	return out
}

func renderEvidenceDigestSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatDigestMessage(digestModel.slackSummary())
	if err != nil {
		return nil, fmt.Errorf("failed to format slack message for digest: %w", err)
	}

	return message, nil
}

func (s *Service) dispatchEvidenceDigestNotifications(
	ctx context.Context,
	summary *EvidenceSummary,
	webBaseURL string,
	generatedAt time.Time,
	includeConfiguredDestinations bool,
	includeSubscribedUsers bool,
) error {
	request := notification.FanoutRequest{}
	dispatchOptions := evidenceDigestDispatchOptions(generatedAt)

	if includeConfiguredDestinations {
		targets, err := s.configuredDigestTargets(ctx)
		if err != nil {
			return err
		}

		audiences := audiencesForTargets(targets)
		if len(audiences) > 0 {
			request.Requests = append(request.Requests, notification.Request{
				Kind:      evidenceDigestKind,
				Audiences: audiences,
				Model:     newEvidenceDigestNotificationModel(summary, "", webBaseURL, generatedAt),
				Options:   dispatchOptions,
			})
		}
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

func (s *Service) configuredDigestTargets(ctx context.Context) ([]notification.Target, error) {
	if s.db == nil {
		return []notification.Target{}, nil
	}

	return notification.NewGORMSystemDestinationRepository(s.db, notificationproviders.NewLookup()).
		ListTargetsBySubscriptionGate(ctx, notification.SubscriptionGateEvidenceDigest)
}

func audiencesForTargets(targets []notification.Target) []notification.Audience {
	if len(targets) == 0 {
		return nil
	}

	audiences := make([]notification.Audience, 0, len(targets))
	for i := range targets {
		address := make(map[string]string, len(targets[i].Address))
		for key, value := range targets[i].Address {
			address[key] = value
		}

		audiences = append(audiences, notification.Audience{
			Direct: &notification.DirectAudience{
				Provider: targets[i].Provider,
				Address:  address,
			},
		})
	}

	return audiences
}

func (s *Service) hasGlobalDigestDestinations(ctx context.Context) bool {
	targets, err := s.configuredDigestTargets(ctx)
	if err != nil {
		s.logger.Warnw("Failed to resolve configured digest destinations", "error", err)
		return false
	}
	if len(targets) == 0 {
		s.logger.Debug("Configured digest destinations are missing; skipping optional digest system notifications")
		return false
	}

	return true
}
