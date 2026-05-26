package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
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

type digestNotificationData struct {
	UserName     string
	PeriodLabel  string
	PendingTasks []DigestTask
	OverdueTasks []DigestTask
	MyTasksURL   string
	GeneratedAt  time.Time
}

// WorkflowTaskDigestWorker sends a per-user digest of pending and overdue workflow tasks
type WorkflowTaskDigestWorker struct {
	db                          *gorm.DB
	userRepo                    UserRepository
	webBaseURL                  string
	notificationRuntimeProvider notification.RuntimeProvider
	logger                      *zap.SugaredLogger
}

// NewWorkflowTaskDigestWorker creates a new WorkflowTaskDigestWorker with an injected runtime provider.
func NewWorkflowTaskDigestWorker(
	db *gorm.DB,
	userRepo UserRepository,
	webBaseURL string,
	notificationRuntime notification.RuntimeProvider,
	logger *zap.SugaredLogger,
) *WorkflowTaskDigestWorker {
	return &WorkflowTaskDigestWorker{
		db:                          db,
		userRepo:                    userRepo,
		webBaseURL:                  webBaseURL,
		notificationRuntimeProvider: notificationRuntime,
		logger:                      logger,
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

	notificationService := newWorkflowNotificationServiceFromFactory(
		w.notificationRuntimeProvider.NewRuntimeFactory(nil),
		newNotificationUserRepositoryAdapter(w.userRepo, user),
	)

	if err := notificationService.Dispatch(
		ctx,
		requestWithSourceJobID(buildWorkflowTaskDigestNotificationRequest(args, data), riverJobID(job)),
	); err != nil {
		return fmt.Errorf("dispatch workflow-task-digest notification: %w", err)
	}

	w.logger.Infow("WorkflowTaskDigestWorker: digest notifications sent",
		"user_id", args.UserID,
		"pending", len(pendingTasks),
		"overdue", len(overdueTasks),
		"requested_channel", args.Channel,
	)

	return nil
}
func toSlackDigestTasks(tasks []DigestTask) []slackprovider.WorkflowTaskDigestItem {
	if len(tasks) == 0 {
		return nil
	}

	out := make([]slackprovider.WorkflowTaskDigestItem, 0, len(tasks))
	for _, task := range tasks {
		dueDate := ""
		if task.DueDate != nil {
			dueDate = *task.DueDate
		}
		out = append(out, slackprovider.WorkflowTaskDigestItem{
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
