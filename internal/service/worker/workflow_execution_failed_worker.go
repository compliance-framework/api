package worker

import (
	"context"
	"fmt"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// WorkflowExecutionFailedWorker sends a failure notification email to the workflow instance creator
type WorkflowExecutionFailedWorker struct {
	db                          *gorm.DB
	userRepo                    UserRepository
	webBaseURL                  string
	notificationRuntimeProvider notification.RuntimeProvider
	logger                      *zap.SugaredLogger
}

// NewWorkflowExecutionFailedWorker creates a new WorkflowExecutionFailedWorker
func NewWorkflowExecutionFailedWorker(db *gorm.DB, userRepo UserRepository, webBaseURL string, notificationRuntime notification.RuntimeProvider, logger *zap.SugaredLogger) *WorkflowExecutionFailedWorker {
	return &WorkflowExecutionFailedWorker{
		db:                          db,
		userRepo:                    userRepo,
		webBaseURL:                  webBaseURL,
		notificationRuntimeProvider: notificationRuntime,
		logger:                      logger,
	}
}

// Work sends a failure notification email for the workflow execution identified by job.Args.WorkflowExecutionID
func (w *WorkflowExecutionFailedWorker) Work(ctx context.Context, job *river.Job[WorkflowExecutionFailedArgs]) error {
	args := job.Args

	executionID, err := uuid.Parse(args.WorkflowExecutionID)
	if err != nil {
		w.logger.Warnw("WorkflowExecutionFailedWorker: invalid execution ID, skipping",
			"workflow_execution_id", args.WorkflowExecutionID,
			"error", err,
		)
		return nil
	}

	if w.db == nil {
		return fmt.Errorf("WorkflowExecutionFailedWorker: db is nil")
	}

	var execution workflows.WorkflowExecution
	if err := w.db.WithContext(ctx).
		Preload("WorkflowInstance.WorkflowDefinition").
		Preload("StepExecutions").
		First(&execution, "id = ?", executionID).Error; err != nil {
		return fmt.Errorf("WorkflowExecutionFailedWorker: failed to load execution %s: %w", args.WorkflowExecutionID, err)
	}

	if execution.WorkflowInstance == nil {
		w.logger.Warnw("WorkflowExecutionFailedWorker: workflow instance not found, skipping",
			"workflow_execution_id", args.WorkflowExecutionID,
		)
		return nil
	}

	instance := execution.WorkflowInstance
	if instance.CreatedByID == nil {
		w.logger.Warnw("WorkflowExecutionFailedWorker: instance has no CreatedByID, skipping",
			"workflow_execution_id", args.WorkflowExecutionID,
			"workflow_instance_id", instance.ID,
		)
		return nil
	}

	recipient, err := w.userRepo.FindUserByID(ctx, instance.CreatedByID.String())
	if err != nil {
		w.logger.Warnw("WorkflowExecutionFailedWorker: creator user not found, skipping",
			"workflow_execution_id", args.WorkflowExecutionID,
			"user_id", instance.CreatedByID,
			"error", err,
		)
		return nil
	}

	workflowTitle := ""
	if instance.WorkflowDefinition != nil {
		workflowTitle = instance.WorkflowDefinition.Name
	}

	counts := workflow.CountStepStatuses(execution.StepExecutions)
	failedSteps := counts.Failed
	completedSteps := counts.Completed
	totalSteps := len(execution.StepExecutions)

	failedAt := "unknown"
	if execution.FailedAt != nil {
		failedAt = formatDate(*execution.FailedAt)
	}

	notifier := newWorkflowNotificationServiceFromFactory(
		w.notificationRuntimeProvider.NewRuntimeFactory(nil),
		newNotificationUserRepositoryAdapter(w.userRepo, recipient),
	)

	model := workflowExecutionFailedNotificationModel{
		RecipientName:        recipient.FullName(),
		WorkflowTitle:        workflowTitle,
		WorkflowInstanceName: instance.Name,
		ExecutionID:          execution.ID.String(),
		FailureReason:        execution.FailureReason,
		FailedAt:             failedAt,
		FailedSteps:          failedSteps,
		CompletedSteps:       completedSteps,
		TotalSteps:           totalSteps,
		WorkflowURL:          w.webBaseURL + "/my-tasks",
		MyTasksURL:           w.webBaseURL + "/my-tasks",
	}

	if err := notifier.Dispatch(
		ctx,
		buildWorkflowExecutionFailedNotificationRequest(args, recipient.ID, model),
	); err != nil {
		return fmt.Errorf("dispatch workflow-execution-failed notification: %w", err)
	}

	w.logger.Infow("WorkflowExecutionFailedWorker: failure notification sent",
		"workflow_execution_id", args.WorkflowExecutionID,
		"recipient", recipient.Email,
	)

	return nil
}
