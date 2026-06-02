package worker

import (
	"context"
	"fmt"

	"github.com/compliance-framework/api/internal/service/notification"
	notificationproviders "github.com/compliance-framework/api/internal/service/notification/providers"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/compliance-framework/api/internal/workflow"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// WorkflowExecutionFailedWorker sends workflow execution failure notifications to the
// workflow instance creator using supported delivery targets.
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

// Work sends a workflow execution failure notification for the execution identified
// by job.Args.WorkflowExecutionID.
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
		WorkflowURL:          w.webBaseURL + "/workflow-executions/" + execution.ID.String(),
		MyTasksURL:           w.webBaseURL + "/my-tasks",
	}
	requests := []notification.Request{
		requestWithSourceJobID(buildWorkflowExecutionFailedNotificationRequest(args, recipient.ID, model), riverJobID(job)),
	}

	targets, err := w.configuredWorkflowExecutionFailedTargets(ctx)
	if err != nil {
		return fmt.Errorf("resolve workflow-execution-failed system destinations: %w", err)
	}

	if systemRequest, ok := buildWorkflowExecutionFailedSystemNotificationRequest(args, targets, model); ok {
		requests = append(requests, requestWithSourceJobID(systemRequest, riverJobID(job)))
	}

	if err := notifier.DispatchFanout(
		ctx,
		notification.FanoutRequest{Requests: requests},
	); err != nil {
		return fmt.Errorf("dispatch workflow-execution-failed notification: %w", err)
	}

	w.logger.Infow("WorkflowExecutionFailedWorker: failure notification sent",
		"workflow_execution_id", args.WorkflowExecutionID,
		"recipient", recipient.Email,
		"system_target_count", len(targets),
	)

	return nil
}

func (w *WorkflowExecutionFailedWorker) configuredWorkflowExecutionFailedTargets(ctx context.Context) ([]notification.Target, error) {
	if w.db == nil {
		return []notification.Target{}, nil
	}

	return notification.NewGORMSystemDestinationRepository(w.db, notificationproviders.NewLookup()).
		ListTargetsBySystemNotificationName(ctx, notification.SystemNotificationNameWorkflowExecutionFailed)
}
