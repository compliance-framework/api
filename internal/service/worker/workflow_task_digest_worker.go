package worker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DigestTask represents a single task entry in the digest email
type DigestTask struct {
	StepTitle             string
	WorkflowTitle         string
	WorkflowInstanceTitle string
	DueDate               *string
	StepURL               string
}

type digestNotificationData struct {
	UserName     string
	PeriodLabel  string
	PendingTasks []DigestTask
	OverdueTasks []DigestTask
	MyTasksURL   string
	GeneratedAt  time.Time
}

func (d digestNotificationData) templateData() map[string]interface{} {
	return map[string]interface{}{
		"UserName":     d.UserName,
		"PeriodLabel":  d.PeriodLabel,
		"PendingTasks": d.PendingTasks,
		"OverdueTasks": d.OverdueTasks,
		"MyTasksURL":   d.MyTasksURL,
	}
}

// WorkflowTaskDigestWorker sends a per-user digest of pending and overdue workflow tasks
type WorkflowTaskDigestWorker struct {
	db           *gorm.DB
	emailService EmailService
	slackService SlackService
	userRepo     UserRepository
	webBaseURL   string
	logger       *zap.SugaredLogger
}

// NewWorkflowTaskDigestWorker creates a new WorkflowTaskDigestWorker
func NewWorkflowTaskDigestWorker(db *gorm.DB, emailService EmailService, slackService SlackService, userRepo UserRepository, webBaseURL string, logger *zap.SugaredLogger) *WorkflowTaskDigestWorker {
	return &WorkflowTaskDigestWorker{
		db:           db,
		emailService: emailService,
		slackService: slackService,
		userRepo:     userRepo,
		webBaseURL:   webBaseURL,
		logger:       logger,
	}
}

// Work sends digest notifications for the user identified by job.Args.UserID.
func (w *WorkflowTaskDigestWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskDigestArgs]) error {
	args := job.Args

	user, err := w.userRepo.FindUserByID(ctx, args.UserID)
	if err != nil {
		w.logger.Warnw("WorkflowTaskDigestWorker: user not found, skipping",
			"user_id", args.UserID,
			"error", err,
		)
		return nil
	}

	channels := user.NotificationChannels(notification.NotificationTypeTaskDailyDigest)
	if len(channels) == 0 {
		w.logger.Debugw("WorkflowTaskDigestWorker: user not subscribed to digest, skipping",
			"user_id", args.UserID,
		)
		return nil
	}

	if w.db == nil {
		return fmt.Errorf("WorkflowTaskDigestWorker: db is nil")
	}

	now := time.Now()

	var steps []workflows.StepExecution
	if err := w.db.WithContext(ctx).
		Preload("WorkflowExecution.WorkflowInstance.WorkflowDefinition").
		Preload("WorkflowStepDefinition").
		Where("assigned_to_type = ? AND assigned_to_id = ? AND status IN ?",
			workflows.AssignmentTypeUser.String(),
			args.UserID,
			[]string{
				workflows.StepStatusPending.String(),
				workflows.StepStatusInProgress.String(),
				workflows.StepStatusOverdue.String(),
			},
		).
		Find(&steps).Error; err != nil {
		return fmt.Errorf("WorkflowTaskDigestWorker: failed to query steps for user %s: %w", args.UserID, err)
	}

	if len(steps) == 0 {
		w.logger.Debugw("WorkflowTaskDigestWorker: no tasks for user, skipping",
			"user_id", args.UserID,
		)
		return nil
	}

	var pendingTasks []DigestTask
	var overdueTasks []DigestTask

	for i := range steps {
		step := &steps[i]
		task := buildDigestTask(step)

		if step.Status == workflows.StepStatusOverdue.String() ||
			(step.DueDate != nil && step.DueDate.Before(now)) {
			overdueTasks = append(overdueTasks, task)
		} else {
			pendingTasks = append(pendingTasks, task)
		}
	}

	data := digestNotificationData{
		UserName:     user.FullName(),
		PeriodLabel:  "Daily digest — " + now.Format("Monday, 2 January 2006"),
		PendingTasks: pendingTasks,
		OverdueTasks: overdueTasks,
		MyTasksURL:   w.webBaseURL + "/my-tasks",
		GeneratedAt:  now,
	}

	for _, channel := range channels {
		switch channel {
		case notification.DeliveryChannelEmail:
			if err := w.sendEmail(ctx, args.UserID, user.Email, data); err != nil {
				return err
			}
		case notification.DeliveryChannelSlack:
			if err := w.sendSlack(ctx, args.UserID, user, data); err != nil {
				return err
			}
		default:
			w.logger.Debugw("WorkflowTaskDigestWorker: unsupported channel, skipping",
				"user_id", args.UserID,
				"channel", channel,
			)
		}
	}

	w.logger.Infow("WorkflowTaskDigestWorker: digest notifications sent",
		"user_id", args.UserID,
		"pending", len(pendingTasks),
		"overdue", len(overdueTasks),
		"channels", channels,
	)

	return nil
}

func (w *WorkflowTaskDigestWorker) sendEmail(
	ctx context.Context,
	userID string,
	toAddress string,
	data digestNotificationData,
) error {
	htmlBody, textBody, err := w.emailService.UseTemplate("workflow-task-digest", data.templateData())
	if err != nil {
		w.logger.Errorw("WorkflowTaskDigestWorker: failed to render template",
			"user_id", userID,
			"error", err,
		)
		return fmt.Errorf("failed to render workflow-task-digest template: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{toAddress},
		Subject:  fmt.Sprintf("Your workflow task summary — %s", formatDate(data.GeneratedAt)),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		w.logger.Errorw("WorkflowTaskDigestWorker: failed to send email",
			"user_id", userID,
			"error", err,
		)
		return fmt.Errorf("failed to send workflow-task-digest email: %w", err)
	}

	if !result.Success {
		w.logger.Errorw("WorkflowTaskDigestWorker: email send reported failure",
			"user_id", userID,
			"error", result.Error,
		)
		return fmt.Errorf("workflow-task-digest email send failed: %s", result.Error)
	}

	w.logger.Infow("WorkflowTaskDigestWorker: digest email sent",
		"user_id", userID,
		"message_id", result.MessageID,
	)

	return nil
}

func (w *WorkflowTaskDigestWorker) sendSlack(
	ctx context.Context,
	userID string,
	user NotificationUser,
	data digestNotificationData,
) error {
	if w.slackService == nil || !w.slackService.IsEnabled() {
		w.logger.Debugw("WorkflowTaskDigestWorker: slack service not configured, skipping",
			"user_id", userID,
		)
		return nil
	}

	slackUserID := strings.TrimSpace(user.SlackUserID)
	if slackUserID == "" {
		w.logger.Debugw("WorkflowTaskDigestWorker: user has no Slack link, skipping",
			"user_id", userID,
		)
		return nil
	}

	message, err := slackformatters.FormatWorkflowTaskDigestMessage(
		user.FullName(),
		data.PeriodLabel,
		toSlackDigestTasks(data.PendingTasks),
		toSlackDigestTasks(data.OverdueTasks),
		data.MyTasksURL,
	)
	if err != nil {
		return fmt.Errorf("failed to format workflow-task-digest slack message for user_id=%s: %w", userID, err)
	}

	result, err := w.slackService.SendMessage(ctx, slackUserID, message)
	if err != nil {
		return fmt.Errorf("failed to send workflow-task-digest slack message: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("workflow-task-digest slack message send failed: %s", result.Error)
	}

	w.logger.Infow("WorkflowTaskDigestWorker: digest Slack message sent",
		"user_id", userID,
		"slack_user_id", slackUserID,
		"delivery_id", result.DeliveryID,
	)

	return nil
}

func toSlackDigestTasks(tasks []DigestTask) []slackformatters.WorkflowTaskDigestItem {
	if len(tasks) == 0 {
		return nil
	}

	out := make([]slackformatters.WorkflowTaskDigestItem, 0, len(tasks))
	for _, task := range tasks {
		dueDate := ""
		if task.DueDate != nil {
			dueDate = *task.DueDate
		}
		out = append(out, slackformatters.WorkflowTaskDigestItem{
			StepTitle:             task.StepTitle,
			WorkflowTitle:         task.WorkflowTitle,
			WorkflowInstanceTitle: task.WorkflowInstanceTitle,
			DueDate:               dueDate,
			StepURL:               task.StepURL,
		})
	}
	return out
}

func buildDigestTask(step *workflows.StepExecution) DigestTask {
	task := DigestTask{}
	titles := resolveStepTitles(step)

	task.StepTitle = titles.Step
	task.WorkflowTitle = titles.Workflow
	task.WorkflowInstanceTitle = titles.Instance
	if step.DueDate != nil {
		formatted := formatDate(*step.DueDate)
		task.DueDate = &formatted
	}

	return task
}
