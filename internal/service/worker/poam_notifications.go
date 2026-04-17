package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
)

const (
	poamDeadlineReminderNotificationKind = notification.Kind(JobTypePoamDeadlineReminder)
	poamOpenDigestNotificationKind       = notification.Kind(JobTypePoamOpenDigest)
)

type poamDeadlineReminderNotificationModel struct {
	RecipientName  string
	PoamTitle      string
	SSPName        string
	CurrentStatus  string
	Deadline       string
	MilestoneCount int
	PoamURL        string
}

type poamOpenDigestNotificationModel struct {
	RecipientName          string
	PeriodLabel            string
	NewSinceLastDigest     []PoamDigestEmailItem
	Overdue                []PoamDigestEmailItem
	ApproachingDeadline    []PoamDigestEmailItem
	MilestonesDueSoon      []PoamMilestoneDigestEmailItem
	Stale                  []PoamDigestEmailItem
	PoamListURL            string
	HasNewSinceLast        bool
	HasOverdue             bool
	HasApproachingDeadline bool
	HasMilestonesDueSoon   bool
	HasStale               bool
	GeneratedAt            time.Time
}

type PoamNotificationServiceFactory struct {
	notificationRuntime notification.RuntimeProvider
	definitions         []notification.Definition
}

func NewPoamNotificationServiceFactory(
	notificationRuntime notification.RuntimeProvider,
) *PoamNotificationServiceFactory {
	return &PoamNotificationServiceFactory{
		notificationRuntime: notificationRuntime,
		definitions: []notification.Definition{
			notification.NewDefinition(
				poamDeadlineReminderNotificationKind,
				notification.NotificationTypeRiskNotifications,
				emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
					return renderPoamDeadlineReminderEmail(ctx, model)
				}),
				slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
					return renderPoamDeadlineReminderSlack(ctx, model)
				}),
			),
			notification.NewDefinition(
				poamOpenDigestNotificationKind,
				notification.NotificationTypeRiskNotifications,
				emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
					return renderPoamOpenDigestEmail(ctx, model)
				}),
			),
		},
	}
}

func (f *PoamNotificationServiceFactory) New(users notification.UserRepository) (*notification.Service, error) {
	if f == nil {
		return nil, fmt.Errorf("poam notification service factory is nil")
	}
	if f.notificationRuntime == nil {
		return nil, fmt.Errorf("poam notification runtime is nil")
	}

	return f.notificationRuntime.NewRuntimeFactory(nil).MustNewService(users, f.definitions...), nil
}

func buildPoamDeadlineReminderNotificationRequest(
	args PoamDeadlineReminderArgs,
	recipientName string,
) notification.Request {
	return notification.Request{
		Kind: poamDeadlineReminderNotificationKind,
		Audiences: []notification.Audience{
			{
				User: &notification.UserAudience{UserID: args.RecipientUserID.String()},
			},
		},
		Model: newPoamDeadlineReminderNotificationModel(args, recipientName),
		Options: notification.DispatchOptions{
			CorrelationID: strings.Join([]string{
				JobTypePoamDeadlineReminder,
				strings.TrimSpace(args.PoamItemID.String()),
				strings.TrimSpace(args.RecipientUserID.String()),
				strings.TrimSpace(args.ReminderWindowBucket),
			}, ":"),
			SourceJobKind: JobTypePoamDeadlineReminder,
		},
	}
}

func buildPoamOpenDigestNotificationRequest(args PoamOpenDigestArgs, data poamOpenDigestNotificationData) notification.Request {
	return notification.Request{
		Kind: poamOpenDigestNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.RecipientUserID.String()}},
		},
		Model: newPoamOpenDigestNotificationModel(data),
		Options: notification.DispatchOptions{
			CorrelationID: JobTypePoamOpenDigest + ":" + strings.TrimSpace(args.RecipientUserID.String()),
			SourceJobKind: JobTypePoamOpenDigest,
		},
	}
}

func newPoamDeadlineReminderNotificationModel(
	args PoamDeadlineReminderArgs,
	recipientName string,
) poamDeadlineReminderNotificationModel {
	return poamDeadlineReminderNotificationModel{
		RecipientName:  strings.TrimSpace(recipientName),
		PoamTitle:      strings.TrimSpace(args.PoamTitle),
		SSPName:        strings.TrimSpace(args.SspDisplayName),
		CurrentStatus:  strings.TrimSpace(args.CurrentStatus),
		Deadline:       strings.TrimSpace(args.Deadline),
		MilestoneCount: args.MilestoneCount,
		PoamURL:        strings.TrimSpace(args.PoamURL),
	}
}

func newPoamOpenDigestNotificationModel(data poamOpenDigestNotificationData) poamOpenDigestNotificationModel {
	return poamOpenDigestNotificationModel{
		RecipientName:          strings.TrimSpace(data.RecipientName),
		PeriodLabel:            strings.TrimSpace(data.PeriodLabel),
		NewSinceLastDigest:     data.NewSinceLastDigest,
		Overdue:                data.Overdue,
		ApproachingDeadline:    data.ApproachingDeadline,
		MilestonesDueSoon:      data.MilestonesDueSoon,
		Stale:                  data.Stale,
		PoamListURL:            strings.TrimSpace(data.PoamListURL),
		HasNewSinceLast:        data.HasNewSinceLast,
		HasOverdue:             data.HasOverdue,
		HasApproachingDeadline: data.HasApproachingDeadline,
		HasMilestonesDueSoon:   data.HasMilestonesDueSoon,
		HasStale:               data.HasStale,
		GeneratedAt:            data.GeneratedAt,
	}
}

func (m poamOpenDigestNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"RecipientName":          m.RecipientName,
		"PeriodLabel":            m.PeriodLabel,
		"NewSinceLastDigest":     m.NewSinceLastDigest,
		"Overdue":                m.Overdue,
		"ApproachingDeadline":    m.ApproachingDeadline,
		"MilestonesDueSoon":      m.MilestonesDueSoon,
		"Stale":                  m.Stale,
		"PoamListURL":            m.PoamListURL,
		"HasNewSinceLast":        m.HasNewSinceLast,
		"HasOverdue":             m.HasOverdue,
		"HasApproachingDeadline": m.HasApproachingDeadline,
		"HasMilestonesDueSoon":   m.HasMilestonesDueSoon,
		"HasStale":               m.HasStale,
	}
}

func (m poamDeadlineReminderNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"RecipientName":  m.RecipientName,
		"PoamTitle":      m.PoamTitle,
		"SSPName":        m.SSPName,
		"CurrentStatus":  m.CurrentStatus,
		"Deadline":       m.Deadline,
		"MilestoneCount": m.MilestoneCount,
		"PoamURL":        m.PoamURL,
	}
}

func poamDeadlineReminderNotificationModelFromAny(model any) (poamDeadlineReminderNotificationModel, error) {
	switch typed := model.(type) {
	case poamDeadlineReminderNotificationModel:
		return typed, nil
	case *poamDeadlineReminderNotificationModel:
		if typed == nil {
			return poamDeadlineReminderNotificationModel{}, fmt.Errorf("poam deadline reminder model is required")
		}
		return *typed, nil
	default:
		return poamDeadlineReminderNotificationModel{}, fmt.Errorf("unexpected poam deadline reminder model type %T", model)
	}
}

func poamOpenDigestNotificationModelFromAny(model any) (poamOpenDigestNotificationModel, error) {
	switch typed := model.(type) {
	case poamOpenDigestNotificationModel:
		return typed, nil
	case *poamOpenDigestNotificationModel:
		if typed == nil {
			return poamOpenDigestNotificationModel{}, fmt.Errorf("poam open digest model is required")
		}
		return *typed, nil
	default:
		return poamOpenDigestNotificationModel{}, fmt.Errorf("unexpected poam open digest model type %T", model)
	}
}

func renderPoamDeadlineReminderEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	reminderModel, err := poamDeadlineReminderNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "poam-deadline-reminder",
		TemplateData: reminderModel.templateData(),
		Subject:      fmt.Sprintf("POAM Deadline Approaching: %s", reminderModel.PoamTitle),
		TextBody:     fmt.Sprintf("%s is approaching its deadline. Open: %s", reminderModel.PoamTitle, reminderModel.PoamURL),
	}, nil
}

func renderPoamDeadlineReminderSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	reminderModel, err := poamDeadlineReminderNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}
	message, err := slackprovider.FormatPoamDeadlineReminderMessage(
		reminderModel.RecipientName,
		reminderModel.PoamTitle,
		reminderModel.SSPName,
		reminderModel.CurrentStatus,
		reminderModel.Deadline,
		reminderModel.MilestoneCount,
		reminderModel.PoamURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format poam-deadline-reminder slack message: %w", err)
	}

	return message, nil
}

func renderPoamOpenDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := poamOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "poam-open-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your POAM digest — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your POAM digest is ready.",
	}, nil
}
