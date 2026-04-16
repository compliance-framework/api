package worker

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/riverqueue/river"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DueSoonCheckerArgs represents the arguments for the periodic due-soon checker job
type DueSoonCheckerArgs struct{}

// Kind returns the job kind for River
func (DueSoonCheckerArgs) Kind() string { return "workflow_due_soon_checker" }

// Timeout returns the timeout for the due-soon checker job
func (DueSoonCheckerArgs) Timeout() time.Duration { return 5 * time.Minute }

// DueSoonCheckerWorker scans for step executions due in a week and enqueues reminder notifications.
type DueSoonCheckerWorker struct {
	db         *gorm.DB
	notifier   *notification.Service
	userRepo   UserRepository
	webBaseURL string
	logger     *zap.SugaredLogger
}

// NewDueSoonCheckerWorkerWithRuntimeProvider creates a new DueSoonCheckerWorker with an injected runtime provider.
func NewDueSoonCheckerWorkerWithRuntimeProvider(
	db *gorm.DB,
	emailService EmailService,
	webBaseURL string,
	runtimeProvider notification.RuntimeProvider,
	logger *zap.SugaredLogger,
) *DueSoonCheckerWorker {
	userRepo := NewGORMUserRepository(db)
	if runtimeProvider == nil {
		runtimeProvider = notification.NewStaticRuntimeProvider(nil)
	}

	return &DueSoonCheckerWorker{
		db:         db,
		userRepo:   userRepo,
		webBaseURL: webBaseURL,
		notifier: newWorkflowNotificationServiceFromFactory(
			runtimeProvider.NewRuntimeFactory(nil),
			emailService,
			newNotificationUserRepositoryAdapter(userRepo),
		),
		logger: logger,
	}
}

// Work scans for step executions due in ~1 week and dispatches task-available notifications.
func (w *DueSoonCheckerWorker) Work(ctx context.Context, job *river.Job[DueSoonCheckerArgs]) error {
	if w.db == nil {
		return fmt.Errorf("DueSoonCheckerWorker: db is nil")
	}

	now := time.Now()
	windowStart := now
	windowEnd := now.Add(7 * 24 * time.Hour)

	var steps []workflows.StepExecution
	if err := w.db.WithContext(ctx).
		Preload("WorkflowExecution.WorkflowInstance.WorkflowDefinition").
		Preload("WorkflowStepDefinition").
		Where("status IN ? AND due_date IS NOT NULL AND due_date >= ? AND due_date <= ? AND assigned_to_type = ? AND assigned_to_id != ''",
			[]string{
				workflows.StepStatusPending.String(),
				workflows.StepStatusInProgress.String(),
			},
			windowStart,
			windowEnd,
			workflows.AssignmentTypeUser.String(),
		).
		Find(&steps).Error; err != nil {
		return fmt.Errorf("due-soon checker: failed to query steps: %w", err)
	}

	if len(steps) == 0 {
		w.logger.Infow("DueSoonCheckerWorker: no steps due soon", "window_start", windowStart, "window_end", windowEnd)
		return nil
	}

	dispatched := 0
	for i := range steps {
		step := &steps[i]
		if step.DueDate == nil {
			continue
		}

		titles := resolveStepTitles(step)

		baseArgs := WorkflowTaskDueSoonArgs{
			UserID:                step.AssignedToID,
			StepExecutionID:       step.ID.String(),
			StepTitle:             titles.Step,
			WorkflowTitle:         titles.Workflow,
			WorkflowInstanceTitle: titles.Instance,
			StepURL:               "",
			DueDate:               *step.DueDate,
		}

		userName := ""
		if w.userRepo != nil {
			user, err := w.userRepo.FindUserByID(ctx, step.AssignedToID)
			if err != nil {
				w.logger.Warnw("DueSoonCheckerWorker: user not found, skipping",
					"step_execution_id", step.ID.String(),
					"user_id", step.AssignedToID,
					"error", err,
				)
				continue
			}
			userName = user.FullName()
		}

		if err := w.notifier.Dispatch(
			ctx,
			buildWorkflowTaskDueSoonNotificationRequest(baseArgs, userName, w.webBaseURL),
		); err != nil {
			return fmt.Errorf("due-soon checker: failed to dispatch reminder for step %s: %w", step.ID.String(), err)
		}
		dispatched++
	}

	w.logger.Infow("DueSoonCheckerWorker: dispatched due-soon reminders", "count", dispatched)
	return nil
}
