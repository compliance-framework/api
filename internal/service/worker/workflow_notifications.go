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
	workflowTaskAssignedNotificationKind    = notification.Kind(JobTypeWorkflowTaskAssigned)
	workflowTaskDueSoonNotificationKind     = notification.Kind(JobTypeWorkflowTaskDueSoon)
	workflowTaskDigestNotificationKind      = notification.Kind(JobTypeWorkflowTaskDigest)
	workflowExecutionFailedNotificationKind = notification.Kind(JobTypeWorkflowExecutionFailed)
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

type workflowExecutionFailedNotificationModel struct {
	RecipientName        string
	WorkflowTitle        string
	WorkflowInstanceName string
	ExecutionID          string
	FailureReason        string
	FailedAt             string
	FailedSteps          int
	CompletedSteps       int
	TotalSteps           int
	WorkflowURL          string
	MyTasksURL           string
}

type notificationUserRepositoryAdapter struct {
	base   UserRepository
	cached map[string]NotificationUser
}

func newWorkflowNotificationServiceFromFactory(
	runtimeFactory *notification.RuntimeFactory,
	users notification.UserRepository,
) *notification.Service {
	return runtimeFactory.MustNewService(
		users,
		notification.NewDefinition(
			workflowTaskAssignedNotificationKind,
			notification.NotificationTypeTaskAvailable,
			emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
				return renderWorkflowTaskAssignedEmail(ctx, model)
			}),
			slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
				return renderWorkflowTaskAssignedSlack(ctx, model)
			}),
		),
		notification.NewDefinition(
			workflowTaskDueSoonNotificationKind,
			notification.NotificationTypeTaskAvailable,
			emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
				return renderWorkflowTaskDueSoonEmail(ctx, model)
			}),
			slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
				return renderWorkflowTaskDueSoonSlack(ctx, model)
			}),
		),
		notification.NewDefinition(
			workflowTaskDigestNotificationKind,
			notification.NotificationTypeTaskDailyDigest,
			emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
				return renderWorkflowTaskDigestEmail(ctx, model)
			}),
			slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
				return renderWorkflowTaskDigestSlack(ctx, model)
			}),
		),
		notification.NewDefinition(
			workflowExecutionFailedNotificationKind,
			notification.NotificationTypeUngated,
			emailprovider.TemplateChannel(func(ctx context.Context, model any) (emailprovider.TemplateContent, error) {
				return renderWorkflowExecutionFailedEmail(ctx, model)
			}),
			slackprovider.MessageChannel(func(ctx context.Context, model any) (*slackprovider.Message, error) {
				return renderWorkflowExecutionFailedSlack(ctx, model)
			}),
		),
	)
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

func newWorkflowExecutionFailedNotificationModel(data workflowExecutionFailedNotificationModel) workflowExecutionFailedNotificationModel {
	return workflowExecutionFailedNotificationModel{
		RecipientName:        strings.TrimSpace(data.RecipientName),
		WorkflowTitle:        strings.TrimSpace(data.WorkflowTitle),
		WorkflowInstanceName: strings.TrimSpace(data.WorkflowInstanceName),
		ExecutionID:          strings.TrimSpace(data.ExecutionID),
		FailureReason:        strings.TrimSpace(data.FailureReason),
		FailedAt:             strings.TrimSpace(data.FailedAt),
		FailedSteps:          data.FailedSteps,
		CompletedSteps:       data.CompletedSteps,
		TotalSteps:           data.TotalSteps,
		WorkflowURL:          strings.TrimSpace(data.WorkflowURL),
		MyTasksURL:           strings.TrimSpace(data.MyTasksURL),
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

func buildWorkflowExecutionFailedNotificationRequest(
	args WorkflowExecutionFailedArgs,
	recipientUserID string,
	data workflowExecutionFailedNotificationModel,
) notification.Request {
	return notification.Request{
		Kind: workflowExecutionFailedNotificationKind,
		Audiences: []notification.Audience{
			{User: &notification.UserAudience{UserID: strings.TrimSpace(recipientUserID)}},
		},
		Model: newWorkflowExecutionFailedNotificationModel(data),
		Options: notification.DispatchOptions{
			CorrelationID: JobTypeWorkflowExecutionFailed + ":" + strings.TrimSpace(args.WorkflowExecutionID),
			SourceJobKind: JobTypeWorkflowExecutionFailed,
		},
	}
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

func (m workflowExecutionFailedNotificationModel) templateData() map[string]interface{} {
	return map[string]interface{}{
		"RecipientName":        m.RecipientName,
		"WorkflowTitle":        m.WorkflowTitle,
		"WorkflowInstanceName": m.WorkflowInstanceName,
		"ExecutionID":          m.ExecutionID,
		"FailureReason":        m.FailureReason,
		"FailedAt":             m.FailedAt,
		"FailedSteps":          m.FailedSteps,
		"CompletedSteps":       m.CompletedSteps,
		"TotalSteps":           m.TotalSteps,
		"WorkflowURL":          m.WorkflowURL,
		"MyTasksURL":           m.MyTasksURL,
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

func workflowExecutionFailedNotificationModelFromAny(model any) (workflowExecutionFailedNotificationModel, error) {
	switch typed := model.(type) {
	case workflowExecutionFailedNotificationModel:
		return typed, nil
	case *workflowExecutionFailedNotificationModel:
		if typed == nil {
			return workflowExecutionFailedNotificationModel{}, fmt.Errorf("workflow execution failed model is required")
		}
		return *typed, nil
	default:
		return workflowExecutionFailedNotificationModel{}, fmt.Errorf("unexpected workflow execution failed model type %T", model)
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

func renderWorkflowTaskAssignedEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	assignedModel, err := workflowTaskAssignedNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-assigned",
		TemplateData: map[string]any{
			"UserName":              assignedModel.UserName,
			"StepTitle":             assignedModel.StepTitle,
			"WorkflowTitle":         assignedModel.WorkflowTitle,
			"WorkflowInstanceTitle": assignedModel.WorkflowInstanceTitle,
			"StepURL":               assignedModel.StepURL,
			"MyTasksURL":            assignedModel.MyTasksURL,
			"DueDate":               assignedModel.DueDate,
		},
		Subject:  fmt.Sprintf("Task ready for you: %s — %s", assignedModel.StepTitle, assignedModel.WorkflowTitle),
		TextBody: fmt.Sprintf("%s is assigned to you and due %s. Open: %s", assignedModel.StepTitle, assignedModel.DueDate, assignedModel.StepURL),
	}, nil
}

func renderWorkflowTaskDueSoonEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	dueSoonModel, err := workflowTaskDueSoonNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-due-soon",
		TemplateData: map[string]any{
			"UserName":              dueSoonModel.UserName,
			"StepTitle":             dueSoonModel.StepTitle,
			"WorkflowTitle":         dueSoonModel.WorkflowTitle,
			"WorkflowInstanceTitle": dueSoonModel.WorkflowInstanceTitle,
			"StepURL":               dueSoonModel.StepURL,
			"MyTasksURL":            dueSoonModel.MyTasksURL,
			"DueDate":               dueSoonModel.DueDate,
		},
		Subject:  fmt.Sprintf("Reminder: %s is due soon — %s", dueSoonModel.StepTitle, dueSoonModel.WorkflowTitle),
		TextBody: fmt.Sprintf("%s is due on %s. Open: %s", dueSoonModel.StepTitle, dueSoonModel.DueDate, dueSoonModel.StepURL),
	}, nil
}

func renderWorkflowTaskDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := workflowTaskDigestNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your workflow task summary — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your workflow task digest is ready.",
	}, nil
}

func renderWorkflowExecutionFailedEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	failedModel, err := workflowExecutionFailedNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	instanceName := failedModel.WorkflowInstanceName
	if instanceName == "" {
		instanceName = failedModel.WorkflowTitle
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-execution-failed",
		TemplateData: failedModel.templateData(),
		Subject:      fmt.Sprintf("Workflow execution failed: %s", instanceName),
		TextBody:     fmt.Sprintf("Workflow execution failed for %s. Open: %s", instanceName, failedModel.WorkflowURL),
	}, nil
}

func renderWorkflowTaskAssignedSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	assignedModel, err := workflowTaskAssignedNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatWorkflowTaskAssignedMessage(
		assignedModel.UserName,
		assignedModel.StepTitle,
		assignedModel.WorkflowTitle,
		assignedModel.WorkflowInstanceTitle,
		assignedModel.StepURL,
		assignedModel.DueDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format workflow-task-assigned slack message: %w", err)
	}

	return message, nil
}

func renderWorkflowTaskDueSoonSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	dueSoonModel, err := workflowTaskDueSoonNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatWorkflowTaskDueSoonMessage(
		dueSoonModel.UserName,
		dueSoonModel.StepTitle,
		dueSoonModel.WorkflowTitle,
		dueSoonModel.WorkflowInstanceTitle,
		dueSoonModel.StepURL,
		dueSoonModel.DueDate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format workflow-task-due-soon slack message: %w", err)
	}

	return message, nil
}

func renderWorkflowTaskDigestSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	digestModel, err := workflowTaskDigestNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatWorkflowTaskDigestMessage(
		digestModel.UserName,
		digestModel.PeriodLabel,
		toSlackDigestTasks(digestModel.PendingTasks),
		toSlackDigestTasks(digestModel.OverdueTasks),
		digestModel.MyTasksURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format workflow-task-digest slack message: %w", err)
	}

	return message, nil
}

func renderWorkflowExecutionFailedSlack(_ context.Context, model any) (*slackprovider.Message, error) {
	failedModel, err := workflowExecutionFailedNotificationModelFromAny(model)
	if err != nil {
		return nil, err
	}

	message, err := slackprovider.FormatWorkflowExecutionFailedMessage(
		failedModel.RecipientName,
		failedModel.WorkflowTitle,
		failedModel.WorkflowInstanceName,
		failedModel.ExecutionID,
		failedModel.FailureReason,
		failedModel.FailedAt,
		failedModel.FailedSteps,
		failedModel.CompletedSteps,
		failedModel.TotalSteps,
		failedModel.WorkflowURL,
		failedModel.MyTasksURL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to format workflow-execution-failed slack message: %w", err)
	}

	return message, nil
}
