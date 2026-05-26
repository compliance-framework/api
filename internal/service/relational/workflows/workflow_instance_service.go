package workflows

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// WorkflowInstanceService provides CRUD operations for WorkflowInstance
type WorkflowInstanceService struct {
	db   *gorm.DB
	base *BaseService
}

// NewWorkflowInstanceService creates a new WorkflowInstanceService
func NewWorkflowInstanceService(db *gorm.DB) *WorkflowInstanceService {
	return &WorkflowInstanceService{
		db:   db,
		base: NewBaseService(db),
	}
}

// Create creates a new workflow instance
func (s *WorkflowInstanceService) Create(instance *WorkflowInstance) error {
	return s.base.ValidateAndCreate(instance, "workflow instance", func() error {
		// Set next scheduled time if cadence is provided
		if instance.Cadence != "" && instance.NextScheduledAt == nil {
			nextSchedule := s.calculateNextSchedule(time.Now(), instance.Cadence)
			instance.NextScheduledAt = &nextSchedule
		}

		return s.ValidateInstance(instance)
	})
}

// GetByID retrieves a workflow instance by ID
func (s *WorkflowInstanceService) GetByID(id *uuid.UUID) (*WorkflowInstance, error) {
	var instance WorkflowInstance
	err := s.base.GetByIDWithPreload(&instance, id, "workflow instance",
		"WorkflowDefinition", "WorkflowDefinition.Steps", "RoleAssignments", "Executions")
	if err != nil {
		return nil, err
	}
	return &instance, nil
}

// GetByIDWithContext retrieves a workflow instance by ID with context
func (s *WorkflowInstanceService) GetByIDWithContext(ctx context.Context, id *uuid.UUID) (*WorkflowInstance, error) {
	var instance WorkflowInstance
	err := s.base.GetByIDWithPreloadAndContext(ctx, &instance, id, "workflow instance",
		"WorkflowDefinition", "WorkflowDefinition.Steps", "RoleAssignments", "Executions")
	if err != nil {
		return nil, err
	}
	return &instance, nil
}

// GetAll retrieves all workflow instances with optional filters
func (s *WorkflowInstanceService) GetAll(limit, offset int, filters map[string]interface{}) ([]WorkflowInstance, int64, error) {
	var instances []WorkflowInstance
	var total int64

	query := s.db.Model(&WorkflowInstance{})

	// Apply filters
	if workflowDefID, ok := filters["workflow_definition_id"]; ok {
		query = query.Where("workflow_definition_id = ?", workflowDefID)
	}
	if systemSecurityPlanID, ok := filters["system_security_plan_id"]; ok {
		query = query.Where("system_security_plan_id = ?", systemSecurityPlanID)
	}
	if isActive, ok := filters["is_active"]; ok {
		query = query.Where("is_active = ?", isActive)
	}

	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.Preload("WorkflowDefinition").
		Preload("RoleAssignments").
		Limit(limit).
		Offset(offset).
		Find(&instances).Error

	if err != nil {
		return nil, 0, err
	}

	return instances, total, nil
}

// GetByWorkflowDefinitionID retrieves all instances for a workflow definition
func (s *WorkflowInstanceService) GetByWorkflowDefinitionID(workflowDefID *uuid.UUID) ([]WorkflowInstance, error) {
	var instances []WorkflowInstance
	err := s.db.Where("workflow_definition_id = ?", workflowDefID).
		Preload("RoleAssignments").
		Preload("Executions").
		Find(&instances).Error

	return instances, err
}

// Update updates an existing workflow instance
func (s *WorkflowInstanceService) Update(id *uuid.UUID, updates *WorkflowInstance) error {
	if err := s.base.ValidateUpdatesNotNil(updates); err != nil {
		return err
	}

	if err := s.ValidateInstance(updates); err != nil {
		return err
	}

	// Fetch existing instance once for both cadence check and update
	var existing WorkflowInstance
	if err := s.db.First(&existing, "id = ?", id).Error; err != nil {
		return s.base.HandleRecordNotFoundError(err, id, "workflow instance")
	}

	// If cadence is being updated, recalculate next scheduled time
	if updates.Cadence != "" && existing.Cadence != updates.Cadence {
		nextSchedule := s.calculateNextSchedule(time.Now(), updates.Cadence)
		updates.NextScheduledAt = &nextSchedule
	}

	updates.ID = id
	return s.base.UpdateEntity(&existing, updates, id, "workflow instance")
}

// Delete soft deletes a workflow instance
func (s *WorkflowInstanceService) Delete(id *uuid.UUID) error {
	return s.base.DeleteEntity(&WorkflowInstance{}, id, "workflow instance")
}

// Activate activates a workflow instance
func (s *WorkflowInstanceService) Activate(id *uuid.UUID) error {
	return s.base.ActivateEntity(&WorkflowInstance{}, id)
}

// Deactivate deactivates a workflow instance
func (s *WorkflowInstanceService) Deactivate(id *uuid.UUID) error {
	return s.base.DeactivateEntity(&WorkflowInstance{}, id)
}

// UpdateSchedule updates the next scheduled time for an instance
func (s *WorkflowInstanceService) UpdateSchedule(ctx context.Context, id *uuid.UUID, nextSchedule time.Time) error {
	return s.db.WithContext(ctx).Model(&WorkflowInstance{}).
		Where("id = ?", id).
		Update("next_scheduled_at", nextSchedule).Error
}

// UpdateLastExecuted updates the last executed time for an instance
func (s *WorkflowInstanceService) UpdateLastExecuted(ctx context.Context, id *uuid.UUID, lastExecuted time.Time) error {
	return s.db.WithContext(ctx).Model(&WorkflowInstance{}).
		Where("id = ?", id).
		Update("last_executed_at", lastExecuted).Error
}

// AdvanceSchedule updates the last executed time to now and calculates the next scheduled time
func (s *WorkflowInstanceService) AdvanceSchedule(ctx context.Context, id *uuid.UUID) error {
	instance, err := s.GetByIDWithContext(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()

	// If NextScheduledAt is set, calculate next from there to avoid drift, otherwise from now
	baseTime := now
	if instance.NextScheduledAt != nil {
		baseTime = *instance.NextScheduledAt
	}

	nextSchedule := s.CalculateNextSchedule(baseTime, instance.Cadence)

	return s.db.WithContext(ctx).Model(&WorkflowInstance{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"last_executed_at":  now,
			"next_scheduled_at": nextSchedule,
		}).Error
}

// GetDueInstances retrieves all instances that are due for execution
func (s *WorkflowInstanceService) GetDueInstances(ctx context.Context) ([]WorkflowInstance, error) {
	var instances []WorkflowInstance
	now := time.Now()

	err := s.db.WithContext(ctx).Where("is_active = ? AND next_scheduled_at <= ?", true, now).
		Preload("WorkflowDefinition").
		Preload("WorkflowDefinition.Steps").
		Preload("RoleAssignments").
		Find(&instances).Error

	return instances, err
}

// ValidateInstance validates a workflow instance
func (s *WorkflowInstanceService) ValidateInstance(instance *WorkflowInstance) error {
	if instance == nil {
		return errors.New("workflow instance cannot be nil")
	}
	if instance.GracePeriodDays != nil && *instance.GracePeriodDays < 0 {
		return errors.New("grace period days must be non-negative")
	}

	if err := CombineErrors(
		ValidateStringRequired(instance.Name, "instance name"),
		ValidateStringLength(instance.Name, "instance name", MaxNameLength),
		ValidateUUIDRequired(instance.SystemSecurityPlanID, "system security plan ID"),
		ValidateUUIDRequired(instance.WorkflowDefinitionID, "workflow definition ID"),
		ValidateCadence(instance.Cadence),
	); err != nil {
		return err
	}

	// BCH-1152: instance grace period must be >= definition grace period when both are set.
	if instance.GracePeriodDays != nil && instance.WorkflowDefinitionID != nil {
		var defGrace *int
		s.db.Model(&WorkflowDefinition{}).
			Select("grace_period_days").
			Where("id = ?", instance.WorkflowDefinitionID).
			Scan(&defGrace)
		if defGrace != nil && *instance.GracePeriodDays < *defGrace {
			return errors.New("instance grace period days must be greater than or equal to the workflow definition grace period")
		}
	}

	return nil
}

// CalculateNextSchedule calculates the next scheduled time based on cadence
func (s *WorkflowInstanceService) CalculateNextSchedule(from time.Time, cadence string) time.Time {
	cadenceType := CadenceType(cadence)

	// Handle custom cron expressions
	if cadenceType.IsCron() {
		return s.calculateNextCronSchedule(from, cadenceType.CronExpression())
	}

	switch cadenceType {
	case CadenceDaily:
		return from.AddDate(0, 0, 1)
	case CadenceWeekly:
		return from.AddDate(0, 0, 7)
	case CadenceMonthly:
		return from.AddDate(0, 1, 0)
	case CadenceQuarterly:
		return from.AddDate(0, 3, 0)
	case CadenceAnnually:
		return from.AddDate(1, 0, 0)
	default:
		return from.AddDate(0, 1, 0) // Default to monthly
	}
}

// calculateNextCronSchedule calculates the next scheduled time based on a cron expression.
// NOTE: This parser expects a 6-field cron expression including seconds:
//
//	second minute hour day-of-month month day-of-week
//
// For example, "0 0 9 * * *" means "daily at 9 AM". This differs from the standard
// 5-field Unix cron format (minute hour day-of-month month day-of-week).
//
// If parsing fails (which should not happen if validation passed), it defaults to monthly
// as a defensive fallback.
func (s *WorkflowInstanceService) calculateNextCronSchedule(from time.Time, cronExpr string) time.Time {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	schedule, err := parser.Parse(cronExpr)
	if err != nil {
		// This should not happen if the cron expression was validated during creation.
		// Defaulting to monthly as a defensive fallback.
		return from.AddDate(0, 1, 0)
	}
	return schedule.Next(from)
}

// calculateNextSchedule calculates the next scheduled time based on cadence (deprecated, use CalculateNextSchedule)
func (s *WorkflowInstanceService) calculateNextSchedule(from time.Time, cadence string) time.Time {
	return s.CalculateNextSchedule(from, cadence)
}

// GetBySystemId retrieves all instances for a specific system
func (s *WorkflowInstanceService) GetBySystemId(systemId *uuid.UUID) ([]WorkflowInstance, error) {
	var instances []WorkflowInstance
	err := s.db.Where("system_security_plan_id = ?", systemId).
		Preload("WorkflowDefinition").
		Preload("RoleAssignments").
		Find(&instances).Error

	return instances, err
}
