package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
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

type RiskNotificationServiceFactory struct {
	notificationRuntime notification.RuntimeProvider
	definitions         []notification.Definition
}

func NewRiskNotificationServiceFactory(
	notificationRuntime notification.RuntimeProvider,
) *RiskNotificationServiceFactory {
	return &RiskNotificationServiceFactory{
		notificationRuntime: notificationRuntime,
		definitions: []notification.Definition{
			notification.NewDefinition(
				riskReviewDueReminderNotificationKind,
				notification.NotificationTypeRiskNotifications,
				emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
					return renderRiskReviewDueReminderEmail(ctx, model)
				}),
				slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
					return renderRiskReviewDueReminderSlack(ctx, model)
				}),
			),
			notification.NewDefinition(
				riskReviewOverdueEscalationNotificationKind,
				notification.NotificationTypeRiskNotifications,
				emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
					return renderRiskReviewOverdueEscalationEmail(ctx, model)
				}),
				slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
					return renderRiskReviewOverdueEscalationSlack(ctx, model)
				}),
			),
			notification.NewDefinition(
				riskStaleOpenReminderNotificationKind,
				notification.NotificationTypeRiskNotifications,
				emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
					return renderRiskStaleOpenReminderEmail(ctx, model)
				}),
				slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
					return renderRiskStaleOpenReminderSlack(ctx, model)
				}),
			),
			notification.NewDefinition(
				riskOpenDigestNotificationKind,
				notification.NotificationTypeRiskNotifications,
				emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
					return renderRiskOpenDigestEmail(ctx, model)
				}),
				slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
					return renderRiskOpenDigestSlack(ctx, model)
				}),
			),
		},
	}
}

func (f *RiskNotificationServiceFactory) New(users notification.UserRepository) (*notification.Service, error) {
	if f == nil {
		return nil, fmt.Errorf("risk notification service factory is nil")
	}
	if f.notificationRuntime == nil {
		return nil, fmt.Errorf("risk notification runtime is nil")
	}

	return f.notificationRuntime.NewRuntimeFactory(nil).MustNewService(users, f.definitions...), nil
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

func renderRiskReviewDueReminderSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatRiskReviewDueReminderMessage(
		reminderModel.OwnerName,
		reminderModel.RiskTitle,
		reminderModel.SSPName,
		reminderModel.RiskStatus,
		reminderModel.ReviewDeadline,
		reminderModel.RiskURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format risk-review-due-reminder slack message: %w", err)
	}

	return message, nil
}

func renderRiskReviewOverdueEscalationSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatRiskReviewOverdueEscalationMessage(
		reminderModel.OwnerName,
		reminderModel.RiskTitle,
		reminderModel.SSPName,
		reminderModel.RiskStatus,
		reminderModel.ReviewDeadline,
		reminderModel.RiskURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format risk-review-overdue-escalation slack message: %w", err)
	}

	return message, nil
}

func renderRiskStaleOpenReminderSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatRiskStaleOpenReminderMessage(
		reminderModel.OwnerName,
		reminderModel.RiskTitle,
		reminderModel.SSPName,
		reminderModel.RiskStatus,
		reminderModel.LastSeenAt,
		reminderModel.RiskURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format risk-stale-open-reminder slack message: %w", err)
	}

	return message, nil
}

func renderRiskOpenDigestSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	digestModel, err := riskOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatRiskOpenDigestMessage(
		digestModel.RecipientName,
		digestModel.PeriodLabel,
		toSlackRiskDigestItems(digestModel.NewSinceLastDigest),
		toSlackRiskDigestItems(digestModel.OverdueForAction),
		toSlackRiskDigestItems(digestModel.StaleRisks),
		toSlackRiskDigestItems(digestModel.OverdueReview),
		toSlackRiskDigestItems(digestModel.DueForReview),
		digestModel.RisksURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format risk-open-digest slack message: %w", err)
	}

	return message, nil
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
