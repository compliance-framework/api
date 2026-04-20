package worker

import (
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
)

const (
	poamDeadlineReminderNotificationKind = notification.Kind(JobTypePoamDeadlineReminder)
	poamMilestoneOverdueNotificationKind = notification.Kind(JobTypeMilestoneOverdueReminder)
	poamOverdueNotificationKind          = notification.Kind(JobTypePoamOverdueNotification)
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

type poamOverdueNotificationModel struct {
	RecipientName string
	PoamTitle     string
	SSPName       string
	Deadline      string
	PoamURL       string
}

type poamMilestoneOverdueNotificationModel struct {
	RecipientName  string
	MilestoneTitle string
	PoamTitle      string
	SSPName        string
	DueDate        string
	PoamURL        string
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
			newTypedNotificationDefinition(
				poamDeadlineReminderNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[poamDeadlineReminderNotificationModel]("poam deadline reminder model"),
				renderPoamDeadlineReminderEmail,
				renderPoamDeadlineReminderSlack,
			),
			newTypedNotificationDefinition(
				poamMilestoneOverdueNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[poamMilestoneOverdueNotificationModel]("poam milestone overdue notification model"),
				renderPoamMilestoneOverdueNotificationEmail,
				renderPoamMilestoneOverdueNotificationSlack,
			),
			newTypedNotificationDefinition(
				poamOverdueNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[poamOverdueNotificationModel]("poam overdue notification model"),
				renderPoamOverdueNotificationEmail,
				renderPoamOverdueNotificationSlack,
			),
			newTypedEmailOnlyNotificationDefinition(
				poamOpenDigestNotificationKind,
				notification.NotificationTypeRiskNotifications,
				newNotificationModelDecoder[poamOpenDigestNotificationModel]("poam open digest model"),
				renderPoamOpenDigestEmail,
			),
		},
	}
}

func buildPoamMilestoneOverdueNotificationRequest(
	args MilestoneOverdueReminderArgs,
	recipientName string,
) notification.Request {
	return newUserNotificationRequest(
		poamMilestoneOverdueNotificationKind,
		args.RecipientUserID.String(),
		newPoamMilestoneOverdueNotificationModel(args, recipientName),
		newJobDispatchOptions(JobTypeMilestoneOverdueReminder, "", args.MilestoneID.String(), args.RecipientUserID.String(), args.WeeklyBucket),
	)
}

func buildPoamOverdueNotificationRequest(
	args PoamOverdueNotificationArgs,
	recipientName string,
) notification.Request {
	return newUserNotificationRequest(
		poamOverdueNotificationKind,
		args.RecipientUserID.String(),
		newPoamOverdueNotificationModel(args, recipientName),
		newJobDispatchOptions(JobTypePoamOverdueNotification, "", args.PoamItemID.String(), args.RecipientUserID.String(), args.OverdueWindow),
	)
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
	return newUserNotificationRequest(
		poamDeadlineReminderNotificationKind,
		args.RecipientUserID.String(),
		newPoamDeadlineReminderNotificationModel(args, recipientName),
		newJobDispatchOptions(JobTypePoamDeadlineReminder, "", args.PoamItemID.String(), args.RecipientUserID.String(), args.ReminderWindowBucket),
	)
}

func buildPoamOpenDigestNotificationRequest(args PoamOpenDigestArgs, data poamOpenDigestNotificationData) notification.Request {
	return newUserNotificationRequest(
		poamOpenDigestNotificationKind,
		args.RecipientUserID.String(),
		newPoamOpenDigestNotificationModel(data),
		newJobDispatchOptions(JobTypePoamOpenDigest, "", args.RecipientUserID.String(), args.WindowStart, args.WindowEnd, args.WindowKind),
	)
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

func newPoamOverdueNotificationModel(
	args PoamOverdueNotificationArgs,
	recipientName string,
) poamOverdueNotificationModel {
	return poamOverdueNotificationModel{
		RecipientName: strings.TrimSpace(recipientName),
		PoamTitle:     strings.TrimSpace(args.PoamTitle),
		SSPName:       strings.TrimSpace(args.SspDisplayName),
		Deadline:      strings.TrimSpace(args.Deadline),
		PoamURL:       strings.TrimSpace(args.PoamURL),
	}
}

func newPoamMilestoneOverdueNotificationModel(
	args MilestoneOverdueReminderArgs,
	recipientName string,
) poamMilestoneOverdueNotificationModel {
	return poamMilestoneOverdueNotificationModel{
		RecipientName:  strings.TrimSpace(recipientName),
		MilestoneTitle: strings.TrimSpace(args.MilestoneTitle),
		PoamTitle:      strings.TrimSpace(args.PoamTitle),
		SSPName:        strings.TrimSpace(args.SspDisplayName),
		DueDate:        strings.TrimSpace(args.DueDate),
		PoamURL:        strings.TrimSpace(args.PoamURL),
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

func (m poamOverdueNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"RecipientName": m.RecipientName,
		"PoamTitle":     m.PoamTitle,
		"SSPName":       m.SSPName,
		"Deadline":      m.Deadline,
		"PoamURL":       m.PoamURL,
	}
}

func (m poamMilestoneOverdueNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"RecipientName":  m.RecipientName,
		"MilestoneTitle": m.MilestoneTitle,
		"PoamTitle":      m.PoamTitle,
		"SSPName":        m.SSPName,
		"DueDate":        m.DueDate,
		"PoamURL":        m.PoamURL,
	}
}

func renderPoamDeadlineReminderEmail(reminderModel poamDeadlineReminderNotificationModel) (emailprovider.TemplateContent, error) {
	return emailprovider.TemplateContent{
		TemplateName: "poam-deadline-reminder",
		TemplateData: reminderModel.templateData(),
		Subject:      fmt.Sprintf("POAM Deadline Approaching: %s", reminderModel.PoamTitle),
		TextBody:     fmt.Sprintf("%s is approaching its deadline. Open: %s", reminderModel.PoamTitle, reminderModel.PoamURL),
	}, nil
}

func renderPoamDeadlineReminderSlack(reminderModel poamDeadlineReminderNotificationModel) (*slackprovider.Message, error) {
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

func renderPoamOverdueNotificationEmail(overdueModel poamOverdueNotificationModel) (emailprovider.TemplateContent, error) {
	return emailprovider.TemplateContent{
		TemplateName: "poam-overdue-notification",
		TemplateData: overdueModel.templateData(),
		Subject:      fmt.Sprintf("POAM Item Overdue: %s", overdueModel.PoamTitle),
		TextBody:     fmt.Sprintf("%s is overdue. Open: %s", overdueModel.PoamTitle, overdueModel.PoamURL),
	}, nil
}

func renderPoamOverdueNotificationSlack(overdueModel poamOverdueNotificationModel) (*slackprovider.Message, error) {
	message, err := slackprovider.FormatPoamOverdueNotificationMessage(
		overdueModel.RecipientName,
		overdueModel.PoamTitle,
		overdueModel.SSPName,
		overdueModel.Deadline,
		overdueModel.PoamURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format poam-overdue-notification slack message: %w", err)
	}

	return message, nil
}

func renderPoamMilestoneOverdueNotificationEmail(milestoneModel poamMilestoneOverdueNotificationModel) (emailprovider.TemplateContent, error) {
	return emailprovider.TemplateContent{
		TemplateName: "poam-milestone-overdue-reminder",
		TemplateData: milestoneModel.templateData(),
		Subject:      fmt.Sprintf("POAM Milestone Overdue: %s", milestoneModel.MilestoneTitle),
		TextBody:     fmt.Sprintf("Milestone %s is overdue. Open: %s", milestoneModel.MilestoneTitle, milestoneModel.PoamURL),
	}, nil
}

func renderPoamMilestoneOverdueNotificationSlack(milestoneModel poamMilestoneOverdueNotificationModel) (*slackprovider.Message, error) {
	message, err := slackprovider.FormatPoamMilestoneOverdueReminderMessage(
		milestoneModel.RecipientName,
		milestoneModel.MilestoneTitle,
		milestoneModel.PoamTitle,
		milestoneModel.SSPName,
		milestoneModel.DueDate,
		milestoneModel.PoamURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format poam-milestone-overdue-reminder slack message: %w", err)
	}

	return message, nil
}

func renderPoamOpenDigestEmail(digestModel poamOpenDigestNotificationModel) (emailprovider.TemplateContent, error) {
	return emailprovider.TemplateContent{
		TemplateName: "poam-open-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your POAM digest — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your POAM digest is ready.",
	}, nil
}
