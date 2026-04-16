package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/google/uuid"
)

const (
	riskReviewDueReminderNotificationKind       = notification.Kind(JobTypeRiskReviewDueReminder)
	riskReviewOverdueEscalationNotificationKind = notification.Kind(JobTypeRiskReviewOverdueEscalation)
	riskStaleOpenReminderNotificationKind       = notification.Kind(JobTypeRiskStaleOpenReminder)
	riskOpenDigestNotificationKind              = notification.Kind(JobTypeRiskOpenDigest)
)

type riskReminderNotificationModel struct {
	OwnerName      string
	RiskTitle      string
	SSPName        string
	RiskStatus     string
	ReviewDeadline string
	LastSeenAt     string
	RiskURL        string
}

type riskOpenDigestNotificationModel struct {
	RecipientName       string
	PeriodLabel         string
	NewSinceLastDigest  []RiskDigestEmailItem
	OverdueForAction    []RiskDigestEmailItem
	StaleRisks          []RiskDigestEmailItem
	OverdueReview       []RiskDigestEmailItem
	DueForReview        []RiskDigestEmailItem
	RisksURL            string
	HasNewSinceLast     bool
	HasOverdueForAction bool
	HasStaleRisks       bool
	HasOverdueReview    bool
	HasDueForReview     bool
	GeneratedAt         time.Time
}

func newRiskNotificationServiceFromFactory(
	runtimeFactory *notification.RuntimeFactory,
	emailService EmailService,
	users notification.UserRepository,
) *notification.Service {
	return runtimeFactory.MustNewService(
		users,
		riskReviewDueReminderNotificationDefinition(emailService),
		riskReviewOverdueEscalationNotificationDefinition(emailService),
		riskStaleOpenReminderNotificationDefinition(emailService),
		riskOpenDigestNotificationDefinition(emailService),
	)
}

func riskReviewDueReminderNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              riskReviewDueReminderNotificationKind,
		SubscriptionType:  notification.NotificationTypeRiskNotifications,
		SupportedChannels: allWorkflowNotificationChannels(),
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: notification.EmailChannelRenderer(func(ctx context.Context, model any) (notification.EmailContent, error) {
				return renderRiskReviewDueReminderEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderRiskReviewDueReminderSlack(ctx, model)
			}),
		},
	}
}

func riskReviewOverdueEscalationNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              riskReviewOverdueEscalationNotificationKind,
		SubscriptionType:  notification.NotificationTypeRiskNotifications,
		SupportedChannels: allWorkflowNotificationChannels(),
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: notification.EmailChannelRenderer(func(ctx context.Context, model any) (notification.EmailContent, error) {
				return renderRiskReviewOverdueEscalationEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderRiskReviewOverdueEscalationSlack(ctx, model)
			}),
		},
	}
}

func riskStaleOpenReminderNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              riskStaleOpenReminderNotificationKind,
		SubscriptionType:  notification.NotificationTypeRiskNotifications,
		SupportedChannels: allWorkflowNotificationChannels(),
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: notification.EmailChannelRenderer(func(ctx context.Context, model any) (notification.EmailContent, error) {
				return renderRiskStaleOpenReminderEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderRiskStaleOpenReminderSlack(ctx, model)
			}),
		},
	}
}

func riskOpenDigestNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              riskOpenDigestNotificationKind,
		SubscriptionType:  notification.NotificationTypeRiskNotifications,
		SupportedChannels: allWorkflowNotificationChannels(),
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: notification.EmailChannelRenderer(func(ctx context.Context, model any) (notification.EmailContent, error) {
				return renderRiskOpenDigestEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderRiskOpenDigestSlack(ctx, model)
			}),
		},
	}
}

func buildRiskReviewDueReminderNotificationRequest(
	args RiskReviewDueReminderArgs,
	userName string,
	data riskNotificationData,
) notification.Request {
	return notification.Request{
		Kind: riskReviewDueReminderNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.OwnerUserID.String()}},
		},
		Model:   newRiskReminderNotificationModel(userName, data),
		Options: riskReminderDispatchOptions(JobTypeRiskReviewDueReminder, args.Channel, args.RiskID, args.OwnerUserID),
	}
}

func buildRiskReviewOverdueEscalationNotificationRequest(
	args RiskReviewOverdueEscalationArgs,
	userName string,
	data riskNotificationData,
) notification.Request {
	return notification.Request{
		Kind: riskReviewOverdueEscalationNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.OwnerUserID.String()}},
		},
		Model:   newRiskReminderNotificationModel(userName, data),
		Options: riskReminderDispatchOptions(JobTypeRiskReviewOverdueEscalation, args.Channel, args.RiskID, args.OwnerUserID),
	}
}

func buildRiskStaleOpenReminderNotificationRequest(
	args RiskStaleOpenReminderArgs,
	userName string,
	data riskNotificationData,
) notification.Request {
	return notification.Request{
		Kind: riskStaleOpenReminderNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.OwnerUserID.String()}},
		},
		Model:   newRiskReminderNotificationModel(userName, data),
		Options: riskReminderDispatchOptions(JobTypeRiskStaleOpenReminder, args.Channel, args.RiskID, args.OwnerUserID),
	}
}

func buildRiskOpenDigestNotificationRequest(args RiskOpenDigestArgs, data riskDigestNotificationData) notification.Request {
	return notification.Request{
		Kind: riskOpenDigestNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.RecipientUserID.String()}},
		},
		Model: newRiskOpenDigestNotificationModel(data),
		Options: notification.DispatchOptions{
			RequestedChannel: strings.TrimSpace(args.Channel),
			CorrelationID:    JobTypeRiskOpenDigest + ":" + strings.TrimSpace(args.RecipientUserID.String()),
			SourceJobKind:    JobTypeRiskOpenDigest,
		},
	}
}

func newRiskReminderNotificationModel(userName string, data riskNotificationData) riskReminderNotificationModel {
	ownerName := strings.TrimSpace(userName)
	if ownerName == "" {
		ownerName = strings.TrimSpace(data.OwnerName)
	}

	return riskReminderNotificationModel{
		OwnerName:      ownerName,
		RiskTitle:      strings.TrimSpace(data.RiskTitle),
		SSPName:        strings.TrimSpace(data.SSPName),
		RiskStatus:     strings.TrimSpace(data.RiskStatus),
		ReviewDeadline: strings.TrimSpace(data.ReviewDeadline),
		LastSeenAt:     strings.TrimSpace(data.LastSeenAt),
		RiskURL:        strings.TrimSpace(data.RiskURL),
	}
}

func newRiskOpenDigestNotificationModel(data riskDigestNotificationData) riskOpenDigestNotificationModel {
	return riskOpenDigestNotificationModel{
		RecipientName:       strings.TrimSpace(data.RecipientName),
		PeriodLabel:         strings.TrimSpace(data.PeriodLabel),
		NewSinceLastDigest:  data.NewSinceLastDigest,
		OverdueForAction:    data.OverdueForAction,
		StaleRisks:          data.StaleRisks,
		OverdueReview:       data.OverdueReview,
		DueForReview:        data.DueForReview,
		RisksURL:            strings.TrimSpace(data.RisksURL),
		HasNewSinceLast:     data.HasNewSinceLast,
		HasOverdueForAction: data.HasOverdueForAction,
		HasStaleRisks:       data.HasStaleRisks,
		HasOverdueReview:    data.HasOverdueReview,
		HasDueForReview:     data.HasDueForReview,
		GeneratedAt:         data.GeneratedAt,
	}
}

func riskReminderDispatchOptions(jobKind, requestedChannel string, riskID, ownerUserID uuid.UUID) notification.DispatchOptions {
	parts := []string{strings.TrimSpace(jobKind)}
	if riskID != uuid.Nil {
		parts = append(parts, riskID.String())
	}
	if ownerUserID != uuid.Nil {
		parts = append(parts, ownerUserID.String())
	}

	return notification.DispatchOptions{
		RequestedChannel: strings.TrimSpace(requestedChannel),
		CorrelationID:    strings.Join(parts, ":"),
		SourceJobKind:    strings.TrimSpace(jobKind),
	}
}

func renderRiskReviewDueReminderEmail(_ context.Context, emailService EmailService, model any) (notification.EmailContent, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return notification.EmailContent{}, err
	}

	return renderRiskReminderEmail(emailService, reminderModel, "risk-review-due-reminder", "Risk review due soon")
}

func renderRiskReviewOverdueEscalationEmail(_ context.Context, emailService EmailService, model any) (notification.EmailContent, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return notification.EmailContent{}, err
	}

	return renderRiskReminderEmail(emailService, reminderModel, "risk-review-overdue-escalation", "Risk review overdue")
}

func renderRiskStaleOpenReminderEmail(_ context.Context, emailService EmailService, model any) (notification.EmailContent, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return notification.EmailContent{}, err
	}

	return renderRiskReminderEmail(emailService, reminderModel, "risk-stale-open-reminder", "Stale risk reminder")
}

func renderRiskReminderEmail(
	emailService EmailService,
	model riskReminderNotificationModel,
	templateName string,
	subjectPrefix string,
) (notification.EmailContent, error) {
	if emailService == nil {
		return notification.EmailContent{
			From:     "noreply@localhost",
			Subject:  fmt.Sprintf("%s: %s", subjectPrefix, model.RiskTitle),
			TextBody: riskReminderFallbackText(model),
		}, nil
	}

	htmlBody, textBody, err := emailService.UseTemplate(templateName, model.templateData())
	if err != nil {
		return notification.EmailContent{}, fmt.Errorf("failed to render %s template: %w", templateName, err)
	}

	return notification.EmailContent{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  fmt.Sprintf("%s: %s", subjectPrefix, model.RiskTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}, nil
}

func renderRiskOpenDigestEmail(_ context.Context, emailService EmailService, model any) (notification.EmailContent, error) {
	digestModel, err := riskOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return notification.EmailContent{}, err
	}

	if emailService == nil {
		return notification.EmailContent{
			From:     "noreply@localhost",
			Subject:  fmt.Sprintf("Your risk digest - %s", formatDate(digestModel.GeneratedAt)),
			TextBody: "Your risk digest is ready.",
		}, nil
	}

	htmlBody, textBody, err := emailService.UseTemplate("risk-open-digest", digestModel.templateData())
	if err != nil {
		return notification.EmailContent{}, fmt.Errorf("failed to render risk-open-digest template: %w", err)
	}

	return notification.EmailContent{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  fmt.Sprintf("Your risk digest — %s", formatDate(digestModel.GeneratedAt)),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}, nil
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

func (m riskReminderNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"OwnerName":      m.OwnerName,
		"RiskTitle":      m.RiskTitle,
		"SSPName":        m.SSPName,
		"RiskStatus":     m.RiskStatus,
		"ReviewDeadline": m.ReviewDeadline,
		"LastSeenAt":     m.LastSeenAt,
		"RiskURL":        m.RiskURL,
	}
}

func (m riskOpenDigestNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"RecipientName":       m.RecipientName,
		"PeriodLabel":         m.PeriodLabel,
		"NewSinceLastDigest":  m.NewSinceLastDigest,
		"OverdueForAction":    m.OverdueForAction,
		"StaleRisks":          m.StaleRisks,
		"OverdueReview":       m.OverdueReview,
		"DueForReview":        m.DueForReview,
		"RisksURL":            m.RisksURL,
		"HasNewSinceLast":     m.HasNewSinceLast,
		"HasOverdueForAction": m.HasOverdueForAction,
		"HasStaleRisks":       m.HasStaleRisks,
		"HasOverdueReview":    m.HasOverdueReview,
		"HasDueForReview":     m.HasDueForReview,
	}
}

func riskReminderNotificationModelFromAny(model any) (riskReminderNotificationModel, error) {
	switch typed := model.(type) {
	case riskReminderNotificationModel:
		return typed, nil
	case *riskReminderNotificationModel:
		if typed == nil {
			return riskReminderNotificationModel{}, fmt.Errorf("risk reminder model is required")
		}
		return *typed, nil
	default:
		return riskReminderNotificationModel{}, fmt.Errorf("unexpected risk reminder model type %T", model)
	}
}

func riskOpenDigestNotificationModelFromAny(model any) (riskOpenDigestNotificationModel, error) {
	switch typed := model.(type) {
	case riskOpenDigestNotificationModel:
		return typed, nil
	case *riskOpenDigestNotificationModel:
		if typed == nil {
			return riskOpenDigestNotificationModel{}, fmt.Errorf("risk open digest model is required")
		}
		return *typed, nil
	default:
		return riskOpenDigestNotificationModel{}, fmt.Errorf("unexpected risk open digest model type %T", model)
	}
}
