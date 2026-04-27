package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
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
	IsSystemAudience     bool
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
		newTypedNotificationDefinition(
			notification.NotificationKindWorkflowTaskAssigned,
			notification.SubscriptionGateTaskAvailable,
			newNotificationModelDecoder[workflowTaskAssignedNotificationModel]("workflow task assigned model"),
			renderWorkflowTaskAssignedEmail,
			renderWorkflowTaskAssignedSlack,
		),
		newTypedNotificationDefinition(
			notification.NotificationKindWorkflowTaskDueSoon,
			notification.SubscriptionGateTaskAvailable,
			newNotificationModelDecoder[workflowTaskDueSoonNotificationModel]("workflow task due soon model"),
			renderWorkflowTaskDueSoonEmail,
			renderWorkflowTaskDueSoonSlack,
		),
		newTypedNotificationDefinition(
			notification.NotificationKindWorkflowTaskDigest,
			notification.SubscriptionGateTaskDailyDigest,
			newNotificationModelDecoder[workflowTaskDigestNotificationModel]("workflow task digest model"),
			renderWorkflowTaskDigestEmail,
			renderWorkflowTaskDigestSlack,
		),
		newTypedNotificationDefinition(
			notification.NotificationKindWorkflowExecutionFailed,
			notification.SubscriptionGateUngated,
			newNotificationModelDecoder[workflowExecutionFailedNotificationModel]("workflow execution failed model"),
			renderWorkflowExecutionFailedEmail,
			renderWorkflowExecutionFailedSlack,
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
	return newJobDispatchOptions(jobKind, requestedChannel, stepExecutionID)
}

func buildWorkflowTaskAssignedNotificationRequest(args WorkflowTaskAssignedArgs, userName, webBaseURL string) notification.Request {
	model := newWorkflowTaskAssignedNotificationModel(args, userName, webBaseURL)
	options := taskAvailableDispatchOptions(JobTypeWorkflowTaskAssigned, args.Channel, args.StepExecutionID)
	if args.AssignedToType == workflows.AssignmentTypeEmail.String() {
		return newDirectEmailNotificationRequest(
			notification.NotificationKindWorkflowTaskAssigned,
			args.UserID,
			model,
			options,
		)
	}

	return newUserNotificationRequest(notification.NotificationKindWorkflowTaskAssigned, args.UserID, model, options)
}

func buildWorkflowTaskDueSoonNotificationRequest(args WorkflowTaskDueSoonArgs, userName, webBaseURL string) notification.Request {
	return newUserNotificationRequest(
		notification.NotificationKindWorkflowTaskDueSoon,
		args.UserID,
		newWorkflowTaskDueSoonNotificationModel(args, userName, webBaseURL),
		taskAvailableDispatchOptions(JobTypeWorkflowTaskDueSoon, args.Channel, args.StepExecutionID),
	)
}

func buildWorkflowTaskDigestNotificationRequest(args WorkflowTaskDigestArgs, data digestNotificationData) notification.Request {
	return newUserNotificationRequest(
		notification.NotificationKindWorkflowTaskDigest,
		args.UserID,
		newWorkflowTaskDigestNotificationModel(data),
		newJobDispatchOptions(
			JobTypeWorkflowTaskDigest,
			args.Channel,
			args.UserID,
			data.GeneratedAt.UTC().Format("2006-01-02"),
		),
	)
}

func buildWorkflowExecutionFailedNotificationRequest(
	args WorkflowExecutionFailedArgs,
	recipientUserID string,
	data workflowExecutionFailedNotificationModel,
) notification.Request {
	return newUserNotificationRequest(
		notification.NotificationKindWorkflowExecutionFailed,
		recipientUserID,
		newWorkflowExecutionFailedNotificationModel(data),
		newJobDispatchOptions(JobTypeWorkflowExecutionFailed, "", args.WorkflowExecutionID),
	)
}

func buildWorkflowExecutionFailedSystemNotificationRequest(
	args WorkflowExecutionFailedArgs,
	targets []notification.Target,
	data workflowExecutionFailedNotificationModel,
) (notification.Request, bool) {
	audiences := make([]notification.Audience, 0, len(targets))
	for i := range targets {
		address := make(map[string]string, len(targets[i].Address))
		for key, value := range targets[i].Address {
			address[key] = value
		}

		audiences = append(audiences, notification.Audience{
			Direct: &notification.DirectAudience{
				Provider: targets[i].Provider,
				Address:  address,
			},
		})
	}

	if len(audiences) == 0 {
		return notification.Request{}, false
	}

	systemModel := newWorkflowExecutionFailedNotificationModel(data)
	systemModel.RecipientName = ""
	systemModel.IsSystemAudience = true

	return notification.Request{
		Kind:      notification.NotificationKindWorkflowExecutionFailed,
		Audiences: audiences,
		Model:     systemModel,
		Options:   newJobDispatchOptions(JobTypeWorkflowExecutionFailed, "", args.WorkflowExecutionID),
	}, true
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
		"IsSystemAudience":     m.IsSystemAudience,
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
	if cached, ok := a.cachedUser(userID); ok {
		return convertNotificationUser(cached), nil
	}
	if a == nil || a.base == nil {
		return notification.User{}, fmt.Errorf("notification user repository is not configured")
	}

	user, err := a.base.FindUserByID(ctx, userID)
	if err != nil {
		return notification.User{}, err
	}

	a.cacheUsers(user)
	return convertNotificationUser(user), nil
}

func (a *notificationUserRepositoryAdapter) cachedUser(userID string) (NotificationUser, bool) {
	if a == nil {
		return NotificationUser{}, false
	}

	cached, ok := a.cached[strings.TrimSpace(userID)]
	return cached, ok
}

func (a *notificationUserRepositoryAdapter) cacheUsers(users ...NotificationUser) {
	if a == nil || len(users) == 0 {
		return
	}
	if a.cached == nil {
		a.cached = make(map[string]NotificationUser, len(users))
	}

	for _, user := range users {
		if trimmedID := strings.TrimSpace(user.ID); trimmedID != "" {
			a.cached[trimmedID] = user
		}
	}
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

func (a *notificationUserRepositoryAdapter) ListActiveUsers(_ context.Context) ([]notification.User, error) {
	if a == nil || len(a.cached) == 0 {
		return []notification.User{}, nil
	}

	users := make([]notification.User, 0, len(a.cached))
	for _, user := range a.cached {
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

func renderWorkflowTaskAssignedEmail(assignedModel workflowTaskAssignedNotificationModel) (emailprovider.TemplateContent, error) {
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

func renderWorkflowTaskDueSoonEmail(dueSoonModel workflowTaskDueSoonNotificationModel) (emailprovider.TemplateContent, error) {
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

func renderWorkflowTaskDigestEmail(digestModel workflowTaskDigestNotificationModel) (emailprovider.TemplateContent, error) {
	return emailprovider.TemplateContent{
		TemplateName: "workflow-task-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your workflow task summary — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your workflow task digest is ready.",
	}, nil
}

func renderWorkflowExecutionFailedEmail(failedModel workflowExecutionFailedNotificationModel) (emailprovider.TemplateContent, error) {
	if failedModel.IsSystemAudience {
		return renderWorkflowExecutionFailedSystemEmail(failedModel)
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

func renderWorkflowExecutionFailedSystemEmail(failedModel workflowExecutionFailedNotificationModel) (emailprovider.TemplateContent, error) {
	instanceName := failedModel.WorkflowInstanceName
	if instanceName == "" {
		instanceName = failedModel.WorkflowTitle
	}

	return emailprovider.TemplateContent{
		TemplateName: "workflow-execution-failed-system",
		TemplateData: failedModel.templateData(),
		Subject:      fmt.Sprintf("System alert: workflow execution failed: %s", instanceName),
		TextBody:     fmt.Sprintf("Workflow execution failed for %s. Review details: %s", instanceName, failedModel.WorkflowURL),
	}, nil
}

func renderWorkflowTaskAssignedSlack(assignedModel workflowTaskAssignedNotificationModel) (*slackprovider.Message, error) {
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

func renderWorkflowTaskDueSoonSlack(dueSoonModel workflowTaskDueSoonNotificationModel) (*slackprovider.Message, error) {
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

func renderWorkflowTaskDigestSlack(digestModel workflowTaskDigestNotificationModel) (*slackprovider.Message, error) {
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

func renderWorkflowExecutionFailedSlack(failedModel workflowExecutionFailedNotificationModel) (*slackprovider.Message, error) {
	if failedModel.IsSystemAudience {
		message, err := slackprovider.FormatWorkflowExecutionFailedSystemMessage(
			failedModel.WorkflowTitle,
			failedModel.WorkflowInstanceName,
			failedModel.ExecutionID,
			failedModel.FailureReason,
			failedModel.FailedAt,
			failedModel.FailedSteps,
			failedModel.CompletedSteps,
			failedModel.TotalSteps,
			failedModel.WorkflowURL,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to format workflow-execution-failed system slack message: %w", err)
		}

		return message, nil
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
