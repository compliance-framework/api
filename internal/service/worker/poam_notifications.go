package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
)

const (
	poamOpenDigestNotificationKind = notification.Kind(JobTypePoamOpenDigest)
)

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

func newPoamNotificationServiceFromFactory(
	runtimeFactory *notification.RuntimeFactory,
	emailService EmailService,
	users notification.UserRepository,
) *notification.Service {
	return runtimeFactory.MustNewService(
		users,
		poamOpenDigestNotificationDefinition(emailService),
	)
}

func poamOpenDigestNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              poamOpenDigestNotificationKind,
		SubscriptionType:  notification.NotificationTypeRiskNotifications,
		SupportedChannels: []string{notification.DeliveryChannelEmail},
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: notification.EmailChannelRenderer(func(ctx context.Context, model any) (notification.EmailContent, error) {
				return renderPoamOpenDigestEmail(ctx, emailService, model)
			}),
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

func renderPoamOpenDigestEmail(_ context.Context, emailService EmailService, model any) (notification.EmailContent, error) {
	digestModel, err := poamOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return notification.EmailContent{}, err
	}

	if emailService == nil {
		return notification.EmailContent{
			From:     "noreply@localhost",
			Subject:  fmt.Sprintf("Your POAM digest - %s", formatDate(digestModel.GeneratedAt)),
			TextBody: "Your POAM digest is ready.",
		}, nil
	}

	htmlBody, textBody, err := emailService.UseTemplate("poam-open-digest", digestModel.templateData())
	if err != nil {
		return notification.EmailContent{}, fmt.Errorf("failed to render poam-open-digest template: %w", err)
	}

	return notification.EmailContent{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  fmt.Sprintf("Your POAM digest — %s", formatDate(digestModel.GeneratedAt)),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}, nil
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
