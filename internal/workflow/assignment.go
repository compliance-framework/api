package workflow

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Assignee represents a user or group assigned to a step
type Assignee struct {
	Type string // user, group, email
	ID   string // UUID or email address
}

// AssignmentService handles logic for resolving step assignments
type AssignmentService struct {
	roleAssignmentService RoleAssignmentServiceInterface
	stepExecutionService  StepExecutionAssignmentService
	db                    *gorm.DB
	notificationEnqueuer  NotificationEnqueuer // Optional: for task-assigned notification emails
	logger                *zap.SugaredLogger
}

type StepExecutionAssignmentService interface {
	ReassignWithTx(tx *gorm.DB, id *uuid.UUID, assignedToType, assignedToID string, assignedAt time.Time) error
}

// NewAssignmentService creates a new assignment service
func NewAssignmentService(
	roleAssignmentService RoleAssignmentServiceInterface,
	stepExecutionService StepExecutionAssignmentService,
	db *gorm.DB,
	logger *zap.SugaredLogger,
	notificationEnqueuer NotificationEnqueuer,
) *AssignmentService {
	if stepExecutionService == nil && db != nil {
		stepExecutionService = workflows.NewStepExecutionService(db, nil)
	}
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	return &AssignmentService{
		roleAssignmentService: roleAssignmentService,
		stepExecutionService:  stepExecutionService,
		db:                    db,
		logger:                logger,
		notificationEnqueuer:  notificationEnqueuer,
	}
}

// ResolveStepAssignees resolves assignees for a list of step definitions based on role assignments
func (s *AssignmentService) ResolveStepAssignees(ctx context.Context, instance *workflows.WorkflowInstance, stepDefinitions []workflows.WorkflowStepDefinition) (map[uuid.UUID]Assignee, error) {
	assignments := make(map[uuid.UUID]Assignee)

	for _, stepDef := range stepDefinitions {
		// Skip if no responsible role is defined
		if stepDef.ResponsibleRole == "" {
			continue
		}

		// Look up role assignment
		roleAssignment, err := s.roleAssignmentService.FindAssigneeForRole(instance.ID, stepDef.ResponsibleRole)
		if err != nil {
			if errors.Is(err, workflows.ErrRoleAssignmentNotFound) {
				continue
			}
			return nil, fmt.Errorf("failed to find assignee for role %s: %w", stepDef.ResponsibleRole, err)
		}

		if roleAssignment != nil && roleAssignment.IsActive {
			assignments[*stepDef.ID] = Assignee{
				Type: roleAssignment.AssignedToType,
				ID:   roleAssignment.AssignedToID,
			}
		}
	}

	return assignments, nil
}

var (
	ErrReassignmentNotAllowed = errors.New("step status does not allow reassignment")
	ErrInvalidAssignee        = errors.New("invalid assignee")
)

type BulkReassignResult struct {
	ExecutionID           uuid.UUID
	RoleName              string
	ReassignedCount       int
	ReassignedStepExecIDs []uuid.UUID
}

func (s *AssignmentService) ReassignStep(
	ctx context.Context,
	stepExecutionID uuid.UUID,
	newAssignee Assignee,
	reason string,
	reassignedByUserID *uuid.UUID,
	reassignedByEmail string,
) error {
	if s.db == nil {
		return fmt.Errorf("assignment service database is not configured")
	}
	if s.stepExecutionService == nil {
		return fmt.Errorf("assignment service step execution service is not configured")
	}
	if err := s.validateAssignee(newAssignee); err != nil {
		return err
	}

	var updatedStepExecution workflows.StepExecution
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&updatedStepExecution, stepExecutionID).Error; err != nil {
			return err
		}

		if !isReassignableStatus(updatedStepExecution.Status) {
			return fmt.Errorf("%w: current status is %s", ErrReassignmentNotAllowed, updatedStepExecution.Status)
		}

		if err := s.validateAssigneeExists(tx, newAssignee); err != nil {
			return err
		}

		prevType := updatedStepExecution.AssignedToType
		prevID := updatedStepExecution.AssignedToID

		now := time.Now()
		if err := s.stepExecutionService.ReassignWithTx(tx, updatedStepExecution.ID, newAssignee.Type, newAssignee.ID, now); err != nil {
			return err
		}
		updatedStepExecution.AssignedToType = newAssignee.Type
		updatedStepExecution.AssignedToID = newAssignee.ID

		history := &workflows.StepReassignmentHistory{
			StepExecutionID:        updatedStepExecution.ID,
			WorkflowExecutionID:    updatedStepExecution.WorkflowExecutionID,
			PreviousAssignedToType: prevType,
			PreviousAssignedToID:   prevID,
			NewAssignedToType:      newAssignee.Type,
			NewAssignedToID:        newAssignee.ID,
			Reason:                 reason,
			ReassignedByUserID:     reassignedByUserID,
			ReassignedByEmail:      reassignedByEmail,
		}
		return tx.Create(history).Error
	}); err != nil {
		return err
	}

	if s.notificationEnqueuer != nil &&
		(newAssignee.Type == workflows.AssignmentTypeUser.String() || newAssignee.Type == workflows.AssignmentTypeEmail.String()) {
		if err := s.notificationEnqueuer.EnqueueWorkflowTaskAssigned(ctx, &updatedStepExecution); err != nil {
			// Non-fatal: log but don't fail the reassignment
			s.logger.Errorw("failed to enqueue workflow task assigned notification", "error", err)
		}
	}

	return nil
}

func (s *AssignmentService) BulkReassignByRole(
	ctx context.Context,
	workflowExecutionID uuid.UUID,
	roleName string,
	newAssignee Assignee,
	reason string,
	reassignedByUserID *uuid.UUID,
	reassignedByEmail string,
) (*BulkReassignResult, error) {
	if s.db == nil {
		return nil, fmt.Errorf("assignment service database is not configured")
	}
	if s.stepExecutionService == nil {
		return nil, fmt.Errorf("assignment service step execution service is not configured")
	}
	if roleName == "" {
		return nil, fmt.Errorf("role name is required")
	}
	if err := s.validateAssignee(newAssignee); err != nil {
		return nil, err
	}

	result := &BulkReassignResult{
		ExecutionID:           workflowExecutionID,
		RoleName:              roleName,
		ReassignedStepExecIDs: make([]uuid.UUID, 0),
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var execution workflows.WorkflowExecution
		if err := tx.First(&execution, workflowExecutionID).Error; err != nil {
			return err
		}

		if err := s.validateAssigneeExists(tx, newAssignee); err != nil {
			return err
		}

		var stepExecutions []workflows.StepExecution
		if err := tx.
			Joins("JOIN workflow_step_definitions ON workflow_step_definitions.id = step_executions.workflow_step_definition_id").
			Where("step_executions.workflow_execution_id = ?", workflowExecutionID).
			Where("workflow_step_definitions.responsible_role = ?", roleName).
			Find(&stepExecutions).Error; err != nil {
			return err
		}

		now := time.Now()
		for _, stepExecution := range stepExecutions {
			if !isReassignableStatus(stepExecution.Status) {
				continue
			}

			if err := s.stepExecutionService.ReassignWithTx(tx, stepExecution.ID, newAssignee.Type, newAssignee.ID, now); err != nil {
				return err
			}

			history := &workflows.StepReassignmentHistory{
				StepExecutionID:        stepExecution.ID,
				WorkflowExecutionID:    stepExecution.WorkflowExecutionID,
				PreviousAssignedToType: stepExecution.AssignedToType,
				PreviousAssignedToID:   stepExecution.AssignedToID,
				NewAssignedToType:      newAssignee.Type,
				NewAssignedToID:        newAssignee.ID,
				Reason:                 reason,
				ReassignedByUserID:     reassignedByUserID,
				ReassignedByEmail:      reassignedByEmail,
			}
			if err := tx.Create(history).Error; err != nil {
				return err
			}

			result.ReassignedStepExecIDs = append(result.ReassignedStepExecIDs, *stepExecution.ID)
		}

		result.ReassignedCount = len(result.ReassignedStepExecIDs)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if s.notificationEnqueuer != nil &&
		(newAssignee.Type == workflows.AssignmentTypeUser.String() || newAssignee.Type == workflows.AssignmentTypeEmail.String()) &&
		len(result.ReassignedStepExecIDs) > 0 {
		var reassignedSteps []workflows.StepExecution
		if err := s.db.WithContext(ctx).
			Where("id IN ?", result.ReassignedStepExecIDs).
			Find(&reassignedSteps).Error; err != nil {
			s.logger.Error("failed to load reassigned steps for bulk notification enqueue", "error", err)
			return result, nil
		}

		for i := range reassignedSteps {
			if err := s.notificationEnqueuer.EnqueueWorkflowTaskAssigned(ctx, &reassignedSteps[i]); err != nil {
				s.logger.Error("failed to enqueue workflow task assigned notification for bulk reassignment", "step_execution_id", reassignedSteps[i].ID, "error", err)
			}
		}
	}

	return result, nil
}

func isReassignableStatus(status string) bool {
	return status == workflows.StepStatusPending.String() ||
		status == workflows.StepStatusBlocked.String() ||
		status == workflows.StepStatusInProgress.String() ||
		status == workflows.StepStatusOverdue.String()
}

func (s *AssignmentService) validateAssignee(assignee Assignee) error {
	if err := workflows.ValidateAssignmentType(assignee.Type); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAssignee, err)
	}
	if assignee.ID == "" {
		return fmt.Errorf("%w: assigned to ID is required", ErrInvalidAssignee)
	}
	if len(assignee.ID) > workflows.MaxAssignedToIDLength {
		return fmt.Errorf("%w: assigned to ID cannot exceed %d characters", ErrInvalidAssignee, workflows.MaxAssignedToIDLength)
	}

	switch assignee.Type {
	case workflows.AssignmentTypeUser.String():
		if _, err := uuid.Parse(assignee.ID); err != nil {
			return fmt.Errorf("%w: user assigned-to-id must be a valid UUID", ErrInvalidAssignee)
		}
	case workflows.AssignmentTypeEmail.String():
		if _, err := mail.ParseAddress(assignee.ID); err != nil {
			return fmt.Errorf("%w: assigned-to-id must be a valid email", ErrInvalidAssignee)
		}
	}

	return nil
}

func (s *AssignmentService) validateAssigneeExists(tx *gorm.DB, assignee Assignee) error {
	if assignee.Type != workflows.AssignmentTypeUser.String() {
		return nil
	}

	// UUID format is validated in validateAssignee; this parse is a defensive check
	// to guard against future call sites that might bypass that validation.
	userID, err := uuid.Parse(assignee.ID)
	if err != nil {
		return fmt.Errorf("%w: internal error: user assigned-to-id failed UUID parse after validation", ErrInvalidAssignee)
	}

	var user relational.User
	if err := tx.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: assigned user not found", ErrInvalidAssignee)
		}
		return err
	}

	return nil
}
