package worker

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
)

func renderRiskReviewDueReminderEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return renderRiskReminderTemplateContent(reminderModel, "risk-review-due-reminder", "Risk review due soon"), nil
}

func renderRiskReviewOverdueEscalationEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return renderRiskReminderTemplateContent(reminderModel, "risk-review-overdue-escalation", "Risk review overdue"), nil
}

func renderRiskStaleOpenReminderEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return renderRiskReminderTemplateContent(reminderModel, "risk-stale-open-reminder", "Stale risk reminder"), nil
}

func renderRiskOpenDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := riskOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "risk-open-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your risk digest — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your risk digest is ready.",
	}, nil
}

func renderRiskReminderTemplateContent(
	model riskReminderNotificationModel,
	templateName string,
	subjectPrefix string,
) emailprovider.TemplateContent {
	return emailprovider.TemplateContent{
		TemplateName: templateName,
		TemplateData: model.templateData(),
		Subject:      fmt.Sprintf("%s: %s", subjectPrefix, model.RiskTitle),
		TextBody:     riskReminderFallbackText(model),
	}
}

func riskReminderFallbackText(model riskReminderNotificationModel) string {
	parts := []string{model.RiskTitle}
	if reviewDeadline := strings.TrimSpace(model.ReviewDeadline); reviewDeadline != "" {
		parts = append(parts, "review deadline "+reviewDeadline)
	}
	if lastSeenAt := strings.TrimSpace(model.LastSeenAt); lastSeenAt != "" {
		parts = append(parts, "last seen "+lastSeenAt)
	}
	if riskURL := strings.TrimSpace(model.RiskURL); riskURL != "" {
		parts = append(parts, "open "+riskURL)
	}

	return strings.Join(parts, "; ")
}

func NewDirectRiskNotificationServiceFactory(
	emailService EmailService,
	slackService SlackService,
) *RiskNotificationServiceFactory {
	return NewRiskNotificationServiceFactory(
		newWorkerNotificationRuntimeProvider(
			emailService,
			slackService,
			func() notification.WorkerEnqueuer { return nil },
		),
	)
}
