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
	workflowTaskAssignedNotificationKind = notification.Kind(JobTypeWorkflowTaskAssigned)
	workflowTaskDueSoonNotificationKind  = notification.Kind(JobTypeWorkflowTaskDueSoon)
	workflowTaskDigestNotificationKind   = notification.Kind(JobTypeWorkflowTaskDigest)
)

type workflowTaskAssignedNotificationModel struct {
	UserName              string
	StepTitle             string
	WorkflowTitle         string
	WorkflowInstanceTitle string
	StepURL               string
	MyTasksURL            string
	DueDate               string
}

type workflowTaskDueSoonNotificationModel struct {
	UserName              string
	StepTitle             string
	WorkflowTitle         string
	WorkflowInstanceTitle string
	StepURL               string
	MyTasksURL            string
	DueDate               string
}

type workflowTaskDigestNotificationModel struct {
	UserName     string
	PeriodLabel  string
	PendingTasks []DigestTask
	OverdueTasks []DigestTask
	MyTasksURL   string
	GeneratedAt  time.Time
}

type notificationUserRepositoryAdapter struct {
	base   UserRepository
	cached map[string]NotificationUser
}

func newWorkflowNotificationServiceFromFactory(
	runtimeFactory *notification.RuntimeFactory,
	emailService EmailService,
	users notification.UserRepository,
) *notification.Service {
	return runtimeFactory.MustNewService(
		users,
		workflowTaskAssignedNotificationDefinition(emailService),
		workflowTaskDueSoonNotificationDefinition(emailService),
		workflowTaskDigestNotificationDefinition(emailService),
	)
}

func workflowTaskAssignedNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              workflowTaskAssignedNotificationKind,
		SubscriptionType:  notification.NotificationTypeTaskAvailable,
		SupportedChannels: []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: emailprovider.Renderer(func(ctx context.Context, model any) (emailprovider.Content, error) {
				return renderWorkflowTaskAssignedEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderWorkflowTaskAssignedSlack(ctx, model)
			}),
		},
	}
}

func workflowTaskDueSoonNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              workflowTaskDueSoonNotificationKind,
		SubscriptionType:  notification.NotificationTypeTaskAvailable,
		SupportedChannels: []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: emailprovider.Renderer(func(ctx context.Context, model any) (emailprovider.Content, error) {
				return renderWorkflowTaskDueSoonEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderWorkflowTaskDueSoonSlack(ctx, model)
			}),
		},
	}
}

func workflowTaskDigestNotificationDefinition(emailService EmailService) notification.Definition {
	return notification.Definition{
		Kind:              workflowTaskDigestNotificationKind,
		SubscriptionType:  notification.NotificationTypeTaskDailyDigest,
		SupportedChannels: []string{notification.DeliveryChannelEmail, notification.DeliveryChannelSlack},
		Renderers: map[string]notification.ChannelRenderer{
			notification.DeliveryChannelEmail: emailprovider.Renderer(func(ctx context.Context, model any) (emailprovider.Content, error) {
				return renderWorkflowTaskDigestEmail(ctx, emailService, model)
			}),
			notification.DeliveryChannelSlack: slackprovider.Renderer(func(ctx context.Context, model any) (slackprovider.Content, error) {
				return renderWorkflowTaskDigestSlack(ctx, model)
			}),
		},
	}
}

func newWorkflowTaskAssignedNotificationModel(args WorkflowTaskAssignedArgs, userName, webBaseURL string) workflowTaskAssignedNotificationModel {
	return workflowTaskAssignedNotificationModel{
		UserName:              strings.TrimSpace(userName),
		StepTitle:             strings.TrimSpace(args.StepTitle),
		WorkflowTitle:         strings.TrimSpace(args.WorkflowTitle),
		WorkflowInstanceTitle: strings.TrimSpace(args.WorkflowInstanceTitle),
		StepURL:               resolveTaskURL(args.StepURL, webBaseURL),
		MyTasksURL:            webBaseURL + "/my-tasks",
		DueDate:               formatDueDate(args.DueDate),
	}
}

func newWorkflowTaskDueSoonNotificationModel(args WorkflowTaskDueSoonArgs, userName, webBaseURL string) workflowTaskDueSoonNotificationModel {
	return workflowTaskDueSoonNotificationModel{
		UserName:              strings.TrimSpace(userName),
		StepTitle:             strings.TrimSpace(args.StepTitle),
		WorkflowTitle:         strings.TrimSpace(args.WorkflowTitle),
		WorkflowInstanceTitle: strings.TrimSpace(args.WorkflowInstanceTitle),
		StepURL:               resolveTaskURL(args.StepURL, webBaseURL),
		MyTasksURL:            webBaseURL + "/my-tasks",
		DueDate:               formatDate(args.DueDate),
	}
}

func newWorkflowTaskDigestNotificationModel(data digestNotificationData) workflowTaskDigestNotificationModel {
	return workflowTaskDigestNotificationModel{
		UserName:     strings.TrimSpace(data.UserName),
		PeriodLabel:  strings.TrimSpace(data.PeriodLabel),
		PendingTasks: data.PendingTasks,
		OverdueTasks: data.OverdueTasks,
		MyTasksURL:   strings.TrimSpace(data.MyTasksURL),
		GeneratedAt:  data.GeneratedAt,
	}
}

func taskAvailableDispatchOptions(jobKind, requestedChannel, stepExecutionID string) notification.DispatchOptions {
	correlationID := ""
	if trimmedStepExecutionID := strings.TrimSpace(stepExecutionID); trimmedStepExecutionID != "" {
		correlationID = jobKind + ":" + trimmedStepExecutionID
	}

	return notification.DispatchOptions{
		RequestedChannel: strings.TrimSpace(requestedChannel),
		CorrelationID:    correlationID,
		SourceJobKind:    jobKind,
	}
}

func buildWorkflowTaskAssignedNotificationRequest(args WorkflowTaskAssignedArgs, userName, webBaseURL string) notification.Request {
	audience := notification.Audience{
		User: &notification.UserAudience{UserID: args.UserID},
	}
	if args.AssignedToType == notification.DeliveryChannelEmail {
		audience = notification.Audience{
			Direct: &notification.DirectAudience{
				Provider: emailprovider.ChannelID,
				Address:  emailprovider.Identity(args.UserID),
			},
		}
	}

	return notification.Request{
		Kind: workflowTaskAssignedNotificationKind,
		Audiences: []notification.Audience{
			audience,
		},
		Model:   newWorkflowTaskAssignedNotificationModel(args, userName, webBaseURL),
		Options: taskAvailableDispatchOptions(JobTypeWorkflowTaskAssigned, args.Channel, args.StepExecutionID),
	}
}

func buildWorkflowTaskDueSoonNotificationRequest(args WorkflowTaskDueSoonArgs, userName, webBaseURL string) notification.Request {
	return notification.Request{
		Kind: workflowTaskDueSoonNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.UserID}},
		},
		Model:   newWorkflowTaskDueSoonNotificationModel(args, userName, webBaseURL),
		Options: taskAvailableDispatchOptions(JobTypeWorkflowTaskDueSoon, args.Channel, args.StepExecutionID),
	}
}

func buildWorkflowTaskDigestNotificationRequest(args WorkflowTaskDigestArgs, data digestNotificationData) notification.Request {
	return notification.Request{
		Kind: workflowTaskDigestNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: args.UserID}},
		},
		Model: newWorkflowTaskDigestNotificationModel(data),
		Options: notification.DispatchOptions{
			RequestedChannel: strings.TrimSpace(args.Channel),
			CorrelationID:    JobTypeWorkflowTaskDigest + ":" + strings.TrimSpace(args.UserID),
			SourceJobKind:    JobTypeWorkflowTaskDigest,
		},
	}
}

func renderWorkflowTaskAssignedEmail(_ context.Context, emailService EmailService, model any) (emailprovider.Content, error) {
	assignedModel, err := workflowTaskAssignedNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.Content{}, err
	}

	if emailService == nil {
		return emailprovider.Content{
			From:     "noreply@localhost",
			Subject:  fmt.Sprintf("Task ready for you: %s - %s", assignedModel.StepTitle, assignedModel.WorkflowTitle),
			TextBody: fmt.Sprintf("%s is assigned to you and due %s. Open: %s", assignedModel.StepTitle, assignedModel.DueDate, assignedModel.StepURL),
		}, nil
	}

	htmlBody, textBody, err := emailService.UseTemplate("workflow-task-assigned", map[string]interface{}{
		"UserName":              assignedModel.UserName,
		"StepTitle":             assignedModel.StepTitle,
		"WorkflowTitle":         assignedModel.WorkflowTitle,
		"WorkflowInstanceTitle": assignedModel.WorkflowInstanceTitle,
		"StepURL":               assignedModel.StepURL,
		"MyTasksURL":            assignedModel.MyTasksURL,
		"DueDate":               assignedModel.DueDate,
	})
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render workflow-task-assigned template: %w", err)
	}

	return emailprovider.Content{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  fmt.Sprintf("Task ready for you: %s — %s", assignedModel.StepTitle, assignedModel.WorkflowTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}, nil
}

func renderWorkflowTaskDueSoonEmail(_ context.Context, emailService EmailService, model any) (emailprovider.Content, error) {
	dueSoonModel, err := workflowTaskDueSoonNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.Content{}, err
	}

	if emailService == nil {
		return emailprovider.Content{
			From:     "noreply@localhost",
			Subject:  fmt.Sprintf("Reminder: %s is due soon - %s", dueSoonModel.StepTitle, dueSoonModel.WorkflowTitle),
			TextBody: fmt.Sprintf("%s is due on %s. Open: %s", dueSoonModel.StepTitle, dueSoonModel.DueDate, dueSoonModel.StepURL),
		}, nil
	}

	htmlBody, textBody, err := emailService.UseTemplate("workflow-task-due-soon", map[string]interface{}{
		"UserName":              dueSoonModel.UserName,
		"StepTitle":             dueSoonModel.StepTitle,
		"WorkflowTitle":         dueSoonModel.WorkflowTitle,
		"WorkflowInstanceTitle": dueSoonModel.WorkflowInstanceTitle,
		"StepURL":               dueSoonModel.StepURL,
		"MyTasksURL":            dueSoonModel.MyTasksURL,
		"DueDate":               dueSoonModel.DueDate,
	})
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render workflow-task-due-soon template: %w", err)
	}

	return emailprovider.Content{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  fmt.Sprintf("Reminder: %s is due soon — %s", dueSoonModel.StepTitle, dueSoonModel.WorkflowTitle),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}, nil
}

func renderWorkflowTaskDigestEmail(_ context.Context, emailService EmailService, model any) (emailprovider.Content, error) {
	digestModel, err := workflowTaskDigestNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.Content{}, err
	}

	if emailService == nil {
		return emailprovider.Content{
			From:     "noreply@localhost",
			Subject:  fmt.Sprintf("Your workflow task summary - %s", formatDate(digestModel.GeneratedAt)),
			TextBody: "Your workflow task digest is ready.",
		}, nil
	}

	htmlBody, textBody, err := emailService.UseTemplate("workflow-task-digest", digestModel.templateData())
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render workflow-task-digest template: %w", err)
	}

	return emailprovider.Content{
		From:     emailService.GetDefaultFromAddress(),
		Subject:  fmt.Sprintf("Your workflow task summary — %s", formatDate(digestModel.GeneratedAt)),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}, nil
}

func workflowTaskAssignedNotificationModelFromAny(model any) (workflowTaskAssignedNotificationModel, error) {
	switch typed := model.(type) {
	case workflowTaskAssignedNotificationModel:
		return typed, nil
	case *workflowTaskAssignedNotificationModel:
		if typed == nil {
			return workflowTaskAssignedNotificationModel{}, fmt.Errorf("workflow task assigned model is required")
		}
		return *typed, nil
	default:
		return workflowTaskAssignedNotificationModel{}, fmt.Errorf("unexpected workflow task assigned model type %T", model)
	}
}

func workflowTaskDueSoonNotificationModelFromAny(model any) (workflowTaskDueSoonNotificationModel, error) {
	switch typed := model.(type) {
	case workflowTaskDueSoonNotificationModel:
		return typed, nil
	case *workflowTaskDueSoonNotificationModel:
		if typed == nil {
			return workflowTaskDueSoonNotificationModel{}, fmt.Errorf("workflow task due soon model is required")
		}
		return *typed, nil
	default:
		return workflowTaskDueSoonNotificationModel{}, fmt.Errorf("unexpected workflow task due soon model type %T", model)
	}
}

func (m workflowTaskDigestNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"UserName":     m.UserName,
		"PeriodLabel":  m.PeriodLabel,
		"PendingTasks": m.PendingTasks,
		"OverdueTasks": m.OverdueTasks,
		"MyTasksURL":   m.MyTasksURL,
	}
}

func workflowTaskDigestNotificationModelFromAny(model any) (workflowTaskDigestNotificationModel, error) {
	switch typed := model.(type) {
	case workflowTaskDigestNotificationModel:
		return typed, nil
	case *workflowTaskDigestNotificationModel:
		if typed == nil {
			return workflowTaskDigestNotificationModel{}, fmt.Errorf("workflow task digest model is required")
		}
		return *typed, nil
	default:
		return workflowTaskDigestNotificationModel{}, fmt.Errorf("unexpected workflow task digest model type %T", model)
	}
}

func newNotificationUserRepositoryAdapter(base UserRepository, cachedUsers ...NotificationUser) *notificationUserRepositoryAdapter {
	adapter := &notificationUserRepositoryAdapter{
		base:   base,
		cached: make(map[string]NotificationUser, len(cachedUsers)),
	}

	for _, user := range cachedUsers {
		if trimmedID := strings.TrimSpace(user.ID); trimmedID != "" {
			adapter.cached[trimmedID] = user
		}
	}

	return adapter
}

func (a *notificationUserRepositoryAdapter) FindUserByID(ctx context.Context, userID string) (notification.User, error) {
	if a != nil {
		if cached, ok := a.cached[strings.TrimSpace(userID)]; ok {
			return convertNotificationUser(cached), nil
		}
	}
	if a == nil || a.base == nil {
		return notification.User{}, fmt.Errorf("notification user repository is not configured")
	}

	user, err := a.base.FindUserByID(ctx, userID)
	if err != nil {
		return notification.User{}, err
	}

	return convertNotificationUser(user), nil
}

func (a *notificationUserRepositoryAdapter) ListActiveUsersByNotificationType(_ context.Context, notificationType string) ([]notification.User, error) {
	if a == nil || len(a.cached) == 0 {
		return []notification.User{}, nil
	}

	users := make([]notification.User, 0, len(a.cached))
	for _, user := range a.cached {
		if len(user.NotificationChannels(notificationType)) == 0 {
			continue
		}
		users = append(users, convertNotificationUser(user))
	}

	return users, nil
}

func convertNotificationUser(user NotificationUser) notification.User {
	subscriptions := make([]notification.UserSubscription, 0, len(user.NotificationSubscriptions))
	for _, subscription := range user.NotificationSubscriptions {
		channels := append([]string(nil), subscription.Channels...)
		subscriptions = append(subscriptions, notification.UserSubscription{
			NotificationType: subscription.NotificationType,
			Channels:         channels,
		})
	}

	identities := map[string]map[string]string{}
	if identity := slackprovider.DirectMessageIdentity(user.SlackUserID); len(identity) > 0 {
		identities[notification.DeliveryChannelSlack] = identity
	}

	return notification.User{
		ID:            user.ID,
		Email:         user.Email,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		Identities:    identities,
		Subscriptions: subscriptions,
	}
}
