package worker

import (
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
			newTypedNotificationDefinition(
				riskReviewDueReminderNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[riskReminderNotificationModel]("risk reminder model"),
				renderRiskReviewDueReminderEmail,
				renderRiskReviewDueReminderSlack,
			),
			newTypedNotificationDefinition(
				riskReviewOverdueEscalationNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[riskReminderNotificationModel]("risk reminder model"),
				renderRiskReviewOverdueEscalationEmail,
				renderRiskReviewOverdueEscalationSlack,
			),
			newTypedNotificationDefinition(
				riskStaleOpenReminderNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[riskReminderNotificationModel]("risk reminder model"),
				renderRiskStaleOpenReminderEmail,
				renderRiskStaleOpenReminderSlack,
			),
			newTypedNotificationDefinition(
				riskOpenDigestNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[riskOpenDigestNotificationModel]("risk open digest model"),
				renderRiskOpenDigestEmail,
				renderRiskOpenDigestSlack,
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
	return newUserNotificationRequest(
		riskReviewDueReminderNotificationKind,
		args.OwnerUserID.String(),
		newRiskReminderNotificationModel(userName, data),
		riskReminderDispatchOptions(JobTypeRiskReviewDueReminder, args.Channel, args.RiskID, args.OwnerUserID),
	)
}

func buildRiskReviewOverdueEscalationNotificationRequest(
	args RiskReviewOverdueEscalationArgs,
	userName string,
	data riskNotificationData,
) notification.Request {
	return newUserNotificationRequest(
		riskReviewOverdueEscalationNotificationKind,
		args.OwnerUserID.String(),
		newRiskReminderNotificationModel(userName, data),
		riskReminderDispatchOptions(JobTypeRiskReviewOverdueEscalation, args.Channel, args.RiskID, args.OwnerUserID),
	)
}

func buildRiskStaleOpenReminderNotificationRequest(
	args RiskStaleOpenReminderArgs,
	userName string,
	data riskNotificationData,
) notification.Request {
	return newUserNotificationRequest(
		riskStaleOpenReminderNotificationKind,
		args.OwnerUserID.String(),
		newRiskReminderNotificationModel(userName, data),
		riskReminderDispatchOptions(JobTypeRiskStaleOpenReminder, args.Channel, args.RiskID, args.OwnerUserID),
	)
}

func buildRiskOpenDigestNotificationRequest(args RiskOpenDigestArgs, data riskDigestNotificationData) notification.Request {
	return newUserNotificationRequest(
		riskOpenDigestNotificationKind,
		args.RecipientUserID.String(),
		newRiskOpenDigestNotificationModel(data),
		newJobDispatchOptions(JobTypeRiskOpenDigest, args.Channel, args.RecipientUserID.String()),
	)
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

	if len(parts) > 0 {
		parts = parts[1:]
	}

	return newJobDispatchOptions(jobKind, requestedChannel, parts...)
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

func renderRiskReviewDueReminderEmail(model riskReminderNotificationModel) (emailprovider.TemplateContent, error) {
	return renderRiskReminderTemplateContent(model, "risk-review-due-reminder", "Risk review due soon"), nil
}

func renderRiskReviewOverdueEscalationEmail(model riskReminderNotificationModel) (emailprovider.TemplateContent, error) {
	return renderRiskReminderTemplateContent(model, "risk-review-overdue-escalation", "Risk review overdue"), nil
}

func renderRiskStaleOpenReminderEmail(model riskReminderNotificationModel) (emailprovider.TemplateContent, error) {
	return renderRiskReminderTemplateContent(model, "risk-stale-open-reminder", "Stale risk reminder"), nil
}

func renderRiskOpenDigestEmail(digestModel riskOpenDigestNotificationModel) (emailprovider.TemplateContent, error) {
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

func renderRiskReviewDueReminderSlack(reminderModel riskReminderNotificationModel) (*slackprovider.Message, error) {
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

func renderRiskReviewOverdueEscalationSlack(reminderModel riskReminderNotificationModel) (*slackprovider.Message, error) {
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

func renderRiskStaleOpenReminderSlack(reminderModel riskReminderNotificationModel) (*slackprovider.Message, error) {
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

func renderRiskOpenDigestSlack(digestModel riskOpenDigestNotificationModel) (*slackprovider.Message, error) {
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
