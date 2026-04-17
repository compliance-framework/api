package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
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
	users notification.UserRepository,
) *notification.Service {
	return runtimeFactory.MustNewService(
		users,
		poamOpenDigestNotificationDefinition(),
	)
}

func poamOpenDigestNotificationDefinition() notification.Definition {
	return notification.NewDefinition(
		poamOpenDigestNotificationKind,
		notification.NotificationTypeRiskNotifications,
		emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
			return renderPoamOpenDigestEmail(ctx, model)
		}),
	)
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
