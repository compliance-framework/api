package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OverdueService automates overdue and failed status transitions for workflow and step executions.
type OverdueService struct {
	db                       *gorm.DB
	workflowExecutionService *workflows.WorkflowExecutionService
	stepExecutionService     *workflows.StepExecutionService
	evidenceIntegration      *EvidenceIntegration
	notificationEnqueuer     NotificationEnqueuer // Optional: for workflow notification emails
	logger                   Logger
	defaultGracePeriodDays   int
}

func NewOverdueService(
	db *gorm.DB,
	workflowExecutionService *workflows.WorkflowExecutionService,
	stepExecutionService *workflows.StepExecutionService,
	evidenceIntegration *EvidenceIntegration,
	logger Logger,
	defaultGracePeriodDays int,
) *OverdueService {
	return &OverdueService{
		db:                       db,
		workflowExecutionService: workflowExecutionService,
		stepExecutionService:     stepExecutionService,
		evidenceIntegration:      evidenceIntegration,
		logger:                   logger,
		defaultGracePeriodDays:   defaultGracePeriodDays,
	}
}

// SetNotificationEnqueuer sets the notification enqueuer (optional)
func (s *OverdueService) SetNotificationEnqueuer(enqueuer NotificationEnqueuer) {
	s.notificationEnqueuer = enqueuer
}

// CheckOverdueExecutions marks workflow executions as overdue once due date passes.
func (s *OverdueService) CheckOverdueExecutions(ctx context.Context) (int, error) {
	var executions []workflows.WorkflowExecution
	now := time.Now()
	if err := s.db.WithContext(ctx).
		Where("status IN ? AND due_date IS NOT NULL AND due_date < ?", []string{
			workflows.WorkflowStatusPending.String(),
			workflows.WorkflowStatusInProgress.String(),
		}, now).
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

	executionUpdates, err := s.markExecutionsOverdueFromStepOverdue(ctx)
	if err != nil {
		return updated, err
	}

	s.logger.Infow("Checked overdue workflow steps", "found", len(steps), "updated", updated, "execution_status_updated", executionUpdates)
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
		graceDays := s.resolveExecutionGraceDays(&exec)
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

func (s *OverdueService) resolveExecutionGraceDays(execution *workflows.WorkflowExecution) int {
	if execution.WorkflowInstance != nil && execution.WorkflowInstance.GracePeriodDays != nil {
		return *execution.WorkflowInstance.GracePeriodDays
	}
	if execution.WorkflowInstance != nil && execution.WorkflowInstance.WorkflowDefinition != nil &&
		execution.WorkflowInstance.WorkflowDefinition.GracePeriodDays != nil {
		return *execution.WorkflowInstance.WorkflowDefinition.GracePeriodDays
	}
	return s.defaultGracePeriodDays
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

		if err := tx.Model(&workflows.StepExecution{}).
			Where("workflow_execution_id = ? AND status IN ?", execution.ID, []string{
				workflows.StepStatusPending.String(),
				workflows.StepStatusBlocked.String(),
				workflows.StepStatusInProgress.String(),
				workflows.StepStatusOverdue.String(),
			}).
			Updates(map[string]interface{}{
				"status":         workflows.StepStatusFailed.String(),
				"failed_at":      now,
				"failure_reason": failureReason,
			}).Error; err != nil {
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

func (s *OverdueService) markExecutionsOverdueFromStepOverdue(ctx context.Context) (int, error) {
	var executionIDs []uuid.UUID
	if err := s.db.WithContext(ctx).
		Table("step_executions se").
		Select("DISTINCT se.workflow_execution_id").
		Joins("JOIN workflow_executions we ON we.id = se.workflow_execution_id").
		Where("se.status = ? AND we.status IN ?", workflows.StepStatusOverdue.String(), []string{
			workflows.WorkflowStatusPending.String(),
			workflows.WorkflowStatusInProgress.String(),
		}).
		Scan(&executionIDs).Error; err != nil {
		return 0, fmt.Errorf("failed to query executions with overdue steps: %w", err)
	}

	updated := 0
	for i := range executionIDs {
		executionID := executionIDs[i]
		if err := s.workflowExecutionService.UpdateStatus(ctx, &executionID, workflows.WorkflowStatusOverdue.String()); err != nil {
			s.logger.Errorw("Failed to mark workflow execution overdue from step overdue", "workflow_execution_id", executionID, "error", err)
			continue
		}
		updated++
	}

	return updated, nil
}
