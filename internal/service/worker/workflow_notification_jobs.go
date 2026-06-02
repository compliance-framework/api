package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Job types for workflow notifications.
const (
	JobTypeWorkflowTaskAssigned    = "workflow_task_assigned"
	JobTypeWorkflowTaskDueSoon     = "workflow_task_due_soon"
	JobTypeWorkflowTaskDigest      = "workflow_task_digest"
	JobTypeWorkflowExecutionFailed = "workflow_execution_failed"
)

// WorkflowTaskAssignedArgs represents the arguments for a new-task-assigned notification job.
type WorkflowTaskAssignedArgs struct {
	AssignedToType        string     `json:"assigned_to_type"`
	Channel               string     `json:"channel,omitempty"`
	UserID                string     `json:"user_id"`
	StepExecutionID       string     `json:"step_execution_id"`
	StepTitle             string     `json:"step_title,omitempty"`
	WorkflowTitle         string     `json:"workflow_title,omitempty"`
	WorkflowInstanceTitle string     `json:"workflow_instance_title,omitempty"`
	StepURL               string     `json:"step_url,omitempty"`
	DueDate               *time.Time `json:"due_date,omitempty"`
}

// WorkflowTaskDueSoonArgs represents the arguments for a task-due-soon reminder notification job.
type WorkflowTaskDueSoonArgs struct {
	Channel               string    `json:"channel,omitempty"`
	UserID                string    `json:"user_id"`
	StepExecutionID       string    `json:"step_execution_id"`
	StepTitle             string    `json:"step_title"`
	WorkflowTitle         string    `json:"workflow_title"`
	WorkflowInstanceTitle string    `json:"workflow_instance_title"`
	StepURL               string    `json:"step_url"`
	DueDate               time.Time `json:"due_date"`
}

// WorkflowTaskDigestArgs represents the arguments for a per-user task digest notification job.
type WorkflowTaskDigestArgs struct {
	Channel string `json:"channel,omitempty"`
	UserID  string `json:"user_id"`
}

// WorkflowExecutionFailedArgs represents the arguments for a workflow-execution-failed notification.
type WorkflowExecutionFailedArgs struct {
	WorkflowExecutionID string `json:"workflow_execution_id"`
}

// Kind returns the job kind for River.
func (WorkflowTaskAssignedArgs) Kind() string { return JobTypeWorkflowTaskAssigned }

// Kind returns the job kind for River.
func (WorkflowTaskDueSoonArgs) Kind() string { return JobTypeWorkflowTaskDueSoon }

// Kind returns the job kind for River.
func (WorkflowTaskDigestArgs) Kind() string { return JobTypeWorkflowTaskDigest }

// Kind returns the job kind for River.
func (WorkflowExecutionFailedArgs) Kind() string { return JobTypeWorkflowExecutionFailed }

// Timeout returns the timeout for workflow task assigned jobs.
func (WorkflowTaskAssignedArgs) Timeout() time.Duration { return 30 * time.Second }

// Timeout returns the timeout for workflow task due soon jobs.
func (WorkflowTaskDueSoonArgs) Timeout() time.Duration { return 30 * time.Second }

// Timeout returns the timeout for workflow task digest jobs.
func (WorkflowTaskDigestArgs) Timeout() time.Duration { return 5 * time.Minute }

// Timeout returns the timeout for workflow execution failed jobs.
func (WorkflowExecutionFailedArgs) Timeout() time.Duration { return 30 * time.Second }

func workflowTaskAssignedInsertParams(args WorkflowTaskAssignedArgs) []river.InsertManyParams {
	return []river.InsertManyParams{
		{
			Args:       args,
			InsertOpts: JobInsertOptionsForWorkflowTaskAssignedNotification(),
		},
	}
}

// WorkflowTaskAssignedWorker handles new-task-assigned notification jobs.
type WorkflowTaskAssignedWorker struct {
	userRepo                    UserRepository
	db                          *gorm.DB
	webBaseURL                  string
	notificationRuntimeProvider notification.RuntimeProvider
	logger                      *zap.SugaredLogger
}

// NewWorkflowTaskAssignedWorker creates a new WorkflowTaskAssignedWorker with an injected runtime provider.
func NewWorkflowTaskAssignedWorker(
	userRepo UserRepository,
	webBaseURL string,
	notificationRuntime notification.RuntimeProvider,
	logger *zap.SugaredLogger,
) *WorkflowTaskAssignedWorker {
	return &WorkflowTaskAssignedWorker{
		userRepo:                    userRepo,
		webBaseURL:                  webBaseURL,
		notificationRuntimeProvider: notificationRuntime,
		logger:                      logger,
	}
}

// Work is the River work function for sending new-task-assigned notifications.
func (w *WorkflowTaskAssignedWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskAssignedArgs]) error {
	args := job.Args

	if _, ok := normalizeRequestedDeliveryChannel(args.Channel); !ok {
		w.logger.Warnw("WorkflowTaskAssignedWorker: invalid delivery channel, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"channel", args.Channel,
		)
		return nil
	}

	if args.AssignedToType == workflows.AssignmentTypeEmail.String() {
		return w.dispatchToEmailAddress(ctx, args, riverJobID(job))
	}
	return w.dispatchToUser(ctx, args, riverJobID(job))
}

func (w *WorkflowTaskAssignedWorker) dispatchToUser(ctx context.Context, args WorkflowTaskAssignedArgs, sourceJobID int64) error {
	hydratedArgs, ready, err := w.hydrateNotificationArgs(ctx, args)
	if err != nil {
		return err
	}
	if !ready {
		return nil
	}

	user, err := w.userRepo.FindUserByID(ctx, args.UserID)
	if err != nil {
		w.logger.Warnw("WorkflowTaskAssignedWorker: user not found, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return nil
	}

	notifier := newWorkflowNotificationServiceFromFactory(
		w.notificationRuntimeProvider.NewRuntimeFactory(nil),
		newNotificationUserRepositoryAdapter(w.userRepo, user),
	)

	if err := notifier.Dispatch(
		ctx,
		requestWithSourceJobID(buildWorkflowTaskAssignedNotificationRequest(hydratedArgs, user.FullName(), w.webBaseURL), sourceJobID),
	); err != nil {
		return fmt.Errorf("dispatch workflow-task-assigned notification: %w", err)
	}

	return nil
}

func (w *WorkflowTaskAssignedWorker) dispatchToEmailAddress(ctx context.Context, args WorkflowTaskAssignedArgs, sourceJobID int64) error {
	hydratedArgs, ready, err := w.hydrateNotificationArgs(ctx, args)
	if err != nil {
		return err
	}
	if !ready {
		return nil
	}

	notifier := newWorkflowNotificationServiceFromFactory(
		w.notificationRuntimeProvider.NewRuntimeFactory(nil),
		nil,
	)

	if err := notifier.Dispatch(
		ctx,
		requestWithSourceJobID(buildWorkflowTaskAssignedNotificationRequest(hydratedArgs, "", w.webBaseURL), sourceJobID),
	); err != nil {
		return fmt.Errorf("dispatch workflow-task-assigned direct email notification: %w", err)
	}

	return nil
}

func (w *WorkflowTaskAssignedWorker) hydrateNotificationArgs(
	ctx context.Context,
	args WorkflowTaskAssignedArgs,
) (WorkflowTaskAssignedArgs, bool, error) {
	if w == nil || w.db == nil || strings.TrimSpace(args.StepExecutionID) == "" {
		return args, hasWorkflowTaskAssignedRenderData(args), nil
	}

	var step workflows.StepExecution
	err := w.db.WithContext(ctx).
		Preload("WorkflowExecution.WorkflowInstance.WorkflowDefinition").
		Preload("WorkflowStepDefinition").
		First(&step, "id = ?", args.StepExecutionID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			if hasWorkflowTaskAssignedRenderData(args) {
				return args, true, nil
			}
			w.logger.Warnw("WorkflowTaskAssignedWorker: step execution not found, skipping",
				"step_execution_id", args.StepExecutionID,
				"user_id", args.UserID,
			)
			return args, false, nil
		}
		return args, false, fmt.Errorf("load step execution for workflow-task-assigned notification: %w", err)
	}

	titles := resolveStepTitles(&step)
	hydrated := args
	hydrated.StepTitle = titles.Step
	hydrated.WorkflowTitle = titles.Workflow
	hydrated.WorkflowInstanceTitle = titles.Instance
	hydrated.DueDate = step.DueDate

	return hydrated, hasWorkflowTaskAssignedRenderData(hydrated), nil
}

func hasWorkflowTaskAssignedRenderData(args WorkflowTaskAssignedArgs) bool {
	return strings.TrimSpace(args.StepTitle) != "" ||
		strings.TrimSpace(args.WorkflowTitle) != "" ||
		strings.TrimSpace(args.WorkflowInstanceTitle) != "" ||
		args.DueDate != nil
}

// WorkflowTaskDueSoonWorker handles task-due-soon reminder notification jobs.
type WorkflowTaskDueSoonWorker struct {
	userRepo                    UserRepository
	notificationRuntimeProvider notification.RuntimeProvider
	webBaseURL                  string
	logger                      *zap.SugaredLogger
}

// NewWorkflowTaskDueSoonWorker creates a new WorkflowTaskDueSoonWorker with an injected runtime provider.
func NewWorkflowTaskDueSoonWorker(
	userRepo UserRepository,
	webBaseURL string,
	notificationRuntime notification.RuntimeProvider,
	logger *zap.SugaredLogger,
) *WorkflowTaskDueSoonWorker {
	return &WorkflowTaskDueSoonWorker{
		userRepo:                    userRepo,
		notificationRuntimeProvider: notificationRuntime,
		webBaseURL:                  webBaseURL,
		logger:                      logger,
	}
}

// Work is the River work function for sending task-due-soon reminder notifications.
func (w *WorkflowTaskDueSoonWorker) Work(ctx context.Context, job *river.Job[WorkflowTaskDueSoonArgs]) error {
	args := job.Args

	if _, ok := normalizeRequestedDeliveryChannel(args.Channel); !ok {
		w.logger.Warnw("WorkflowTaskDueSoonWorker: invalid delivery channel, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"channel", args.Channel,
		)
		return nil
	}

	user, err := w.userRepo.FindUserByID(ctx, args.UserID)
	if err != nil {
		w.logger.Warnw("WorkflowTaskDueSoonWorker: user not found, skipping",
			"step_execution_id", args.StepExecutionID,
			"user_id", args.UserID,
			"error", err,
		)
		return nil
	}

	notifier := newWorkflowNotificationServiceFromFactory(
		w.notificationRuntimeProvider.NewRuntimeFactory(nil),
		newNotificationUserRepositoryAdapter(w.userRepo, user),
	)

	if err := notifier.Dispatch(
		ctx,
		requestWithSourceJobID(buildWorkflowTaskDueSoonNotificationRequest(args, user.FullName(), w.webBaseURL), riverJobID(job)),
	); err != nil {
		return fmt.Errorf("dispatch workflow-task-due-soon notification: %w", err)
	}

	return nil
}

// JobInsertOptionsForWorkflowNotification returns insert options for workflow notification jobs.
func JobInsertOptionsForWorkflowNotification() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 5,
	}
}

// JobInsertOptionsForWorkflowTaskAssignedNotification returns insert options for workflow task assignment jobs.
func JobInsertOptionsForWorkflowTaskAssignedNotification() *river.InsertOpts {
	return &river.InsertOpts{
		Queue:       "email",
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs:   true,
			ByPeriod: 5 * time.Minute,
		},
	}
}
