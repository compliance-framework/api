package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// OverdueService automates overdue and failed status transitions for workflow and step executions.
type OverdueService struct {
	db                       *gorm.DB
	workflowExecutionService *workflows.WorkflowExecutionService
	stepExecutionService     *workflows.StepExecutionService
	evidenceIntegration      *EvidenceIntegration
	notificationEnqueuer     NotificationEnqueuer // Optional: for workflow notification emails
	logger                   *zap.SugaredLogger
	defaultGracePeriodDays   int
}

func NewOverdueService(
	db *gorm.DB,
	workflowExecutionService *workflows.WorkflowExecutionService,
	stepExecutionService *workflows.StepExecutionService,
	evidenceIntegration *EvidenceIntegration,
	logger *zap.SugaredLogger,
	defaultGracePeriodDays int,
	notificationEnqueuer NotificationEnqueuer,
) *OverdueService {
	return &OverdueService{
		db:                       db,
		workflowExecutionService: workflowExecutionService,
		stepExecutionService:     stepExecutionService,
		evidenceIntegration:      evidenceIntegration,
		logger:                   logger,
		defaultGracePeriodDays:   defaultGracePeriodDays,
		notificationEnqueuer:     notificationEnqueuer,
	}
}

// CheckOverdueExecutions marks workflow executions as overdue once due date passes.
func (s *OverdueService) CheckOverdueExecutions(ctx context.Context) (int, error) {
	var executions []workflows.WorkflowExecution
	now := time.Now()
	if err := s.db.WithContext(ctx).
		Where(
			`status IN ? AND (
				(due_date IS NOT NULL AND due_date < ?) OR
				EXISTS (
					SELECT 1
					FROM step_executions se
					WHERE se.workflow_execution_id = workflow_executions.id
					  AND se.status = ?
				)
			)`,
			[]string{
				workflows.WorkflowStatusPending.String(),
				workflows.WorkflowStatusInProgress.String(),
			},
			now,
			workflows.StepStatusOverdue.String(),
		).
		Find(&executions).Error; err != nil {
		return 0, fmt.Errorf("failed to query overdue executions: %w", err)
	}

	updated := 0
	for i := range executions {
		if err := s.workflowExecutionService.UpdateStatus(ctx, executions[i].ID, workflows.WorkflowStatusOverdue.String()); err != nil {
			s.logger.Errorw("Failed to mark workflow execution overdue", "workflow_execution_id", executions[i].ID, "error", err)
			continue
		}
		updated++
	}

	s.logger.Infow("Checked overdue workflow executions", "found", len(executions), "updated", updated)
	return updated, nil
}

// CheckOverdueSteps marks incomplete steps as overdue once step due date passes.
func (s *OverdueService) CheckOverdueSteps(ctx context.Context) (int, error) {
	var steps []workflows.StepExecution
	now := time.Now()
	if err := s.db.WithContext(ctx).
		Where("status IN ? AND due_date IS NOT NULL AND due_date < ?", []string{
			workflows.StepStatusPending.String(),
			workflows.StepStatusInProgress.String(),
		}, now).
		Find(&steps).Error; err != nil {
		return 0, fmt.Errorf("failed to query overdue steps: %w", err)
	}

	updated := 0
	for i := range steps {
		if err := s.stepExecutionService.UpdateStatus(ctx, steps[i].ID, workflows.StepStatusOverdue.String()); err != nil {
			s.logger.Errorw("Failed to mark step overdue", "step_execution_id", steps[i].ID, "error", err)
			continue
		}
		updated++
	}

	s.logger.Infow("Checked overdue workflow steps", "found", len(steps), "updated", updated)
	return updated, nil
}

// CheckFailedExecutions marks overdue executions as failed after overdue grace period expires.
func (s *OverdueService) CheckFailedExecutions(ctx context.Context) (int, error) {
	var overdueExecutions []workflows.WorkflowExecution
	if err := s.db.WithContext(ctx).
		Where("status = ? AND overdue_at IS NOT NULL", workflows.WorkflowStatusOverdue.String()).
		Preload("WorkflowInstance").
		Preload("WorkflowInstance.WorkflowDefinition").
		Find(&overdueExecutions).Error; err != nil {
		return 0, fmt.Errorf("failed to query overdue executions for failure transition: %w", err)
	}

	now := time.Now()
	failed := 0
	for i := range overdueExecutions {
		exec := overdueExecutions[i]
		graceDays := ResolveGraceDays(exec.WorkflowInstance, s.defaultGracePeriodDays)
		if exec.OverdueAt == nil || exec.OverdueAt.AddDate(0, 0, graceDays).After(now) {
			continue
		}

		if err := s.failExecutionAndSteps(ctx, &exec); err != nil {
			s.logger.Errorw("Failed to mark overdue execution as failed", "workflow_execution_id", exec.ID, "error", err)
			continue
		}
		failed++
		if s.notificationEnqueuer != nil {
			if notifyErr := s.notificationEnqueuer.EnqueueWorkflowExecutionFailed(ctx, &exec); notifyErr != nil {
				s.logger.Errorw("Failed to enqueue workflow-execution-failed notification", "workflow_execution_id", exec.ID, "error", notifyErr)
			}
		}
	}

	s.logger.Infow("Checked failed workflow executions", "checked", len(overdueExecutions), "failed", failed)
	return failed, nil
}

func (s *OverdueService) failExecutionAndSteps(ctx context.Context, execution *workflows.WorkflowExecution) error {
	now := time.Now()
	failureReason := "overdue - grace period expired"
	executionFailed := false

	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		execResult := tx.Model(&workflows.WorkflowExecution{}).
			Where("id = ? AND status = ?", execution.ID, workflows.WorkflowStatusOverdue.String()).
			Updates(map[string]interface{}{
				"status":         workflows.WorkflowStatusFailed.String(),
				"failed_at":      now,
				"failure_reason": failureReason,
			})
		if execResult.Error != nil {
			return execResult.Error
		}
		if execResult.RowsAffected == 0 {
			return nil
		}
		executionFailed = true

		if err := s.stepExecutionService.BulkFailWithTx(tx, execution.ID, failureReason, now); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}
	if !executionFailed {
		return nil
	}

	if s.evidenceIntegration != nil {
		if err := s.evidenceIntegration.AddExecutionFailureEvidence(ctx, execution.ID); err != nil {
			s.logger.Warnw("Failed to add workflow execution failure evidence", "workflow_execution_id", execution.ID, "error", err)
		}
	}

	return nil
}
