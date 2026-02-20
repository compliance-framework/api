package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
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

// WorkflowTaskDigestWorker sends a per-user digest of pending and overdue workflow tasks
type WorkflowTaskDigestWorker struct {
	db           *gorm.DB
	emailService EmailService
	userRepo     UserRepository
	logger       *zap.SugaredLogger
}

// NewWorkflowTaskDigestWorker creates a new WorkflowTaskDigestWorker
func NewWorkflowTaskDigestWorker(db *gorm.DB, emailService EmailService, userRepo UserRepository, logger *zap.SugaredLogger) *WorkflowTaskDigestWorker {
	return &WorkflowTaskDigestWorker{
		db:           db,
		emailService: emailService,
		userRepo:     userRepo,
		logger:       logger,
	}
}

// Work sends a digest email for the user identified by job.Args.UserID
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

	if !user.TaskDailyDigestSubscribed {
		w.logger.Debugw("WorkflowTaskDigestWorker: user not subscribed to digest, skipping",
			"user_id", args.UserID,
		)
		return nil
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

	userName := user.FirstName
	if user.LastName != "" {
		userName = user.FirstName + " " + user.LastName
	}

	periodLabel := "Daily digest — " + now.Format("Monday, 2 January 2006")

	templateData := map[string]interface{}{
		"UserName":     userName,
		"PeriodLabel":  periodLabel,
		"PendingTasks": pendingTasks,
		"OverdueTasks": overdueTasks,
	}

	htmlBody, textBody, err := w.emailService.UseTemplate("workflow-task-digest", templateData)
	if err != nil {
		w.logger.Errorw("WorkflowTaskDigestWorker: failed to render template",
			"user_id", args.UserID,
			"error", err,
		)
		return fmt.Errorf("failed to render workflow-task-digest template: %w", err)
	}

	message := &types.Message{
		From:     w.emailService.GetDefaultFromAddress(),
		To:       []string{user.Email},
		Subject:  fmt.Sprintf("Your workflow task summary — %s", now.Format("2 Jan 2006")),
		HTMLBody: htmlBody,
		TextBody: textBody,
	}

	result, err := w.emailService.Send(ctx, message)
	if err != nil {
		w.logger.Errorw("WorkflowTaskDigestWorker: failed to send email",
			"user_id", args.UserID,
			"error", err,
		)
		return fmt.Errorf("failed to send workflow-task-digest email: %w", err)
	}

	if !result.Success {
		w.logger.Errorw("WorkflowTaskDigestWorker: email send reported failure",
			"user_id", args.UserID,
			"error", result.Error,
		)
		return fmt.Errorf("workflow-task-digest email send failed: %s", result.Error)
	}

	w.logger.Infow("WorkflowTaskDigestWorker: digest email sent",
		"user_id", args.UserID,
		"pending", len(pendingTasks),
		"overdue", len(overdueTasks),
		"message_id", result.MessageID,
	)

	return nil
}

func buildDigestTask(step *workflows.StepExecution) DigestTask {
	task := DigestTask{}

	if step.WorkflowStepDefinition != nil {
		task.StepTitle = step.WorkflowStepDefinition.Name
	}
	if step.WorkflowExecution != nil && step.WorkflowExecution.WorkflowInstance != nil {
		if step.WorkflowExecution.WorkflowInstance.WorkflowDefinition != nil {
			task.WorkflowTitle = step.WorkflowExecution.WorkflowInstance.WorkflowDefinition.Name
		}
		task.WorkflowInstanceTitle = step.WorkflowExecution.WorkflowInstance.Name
	}
	if step.DueDate != nil {
		formatted := step.DueDate.Format("2006-01-02")
		task.DueDate = &formatted
	}

	return task
}
