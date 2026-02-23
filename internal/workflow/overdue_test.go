package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupOverdueTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&workflows.WorkflowDefinition{},
		&workflows.WorkflowStepDefinition{},
		&workflows.StepDependency{},
		&workflows.StepTrigger{},
		&workflows.WorkflowInstance{},
		&workflows.RoleAssignment{},
		&workflows.WorkflowExecution{},
		&workflows.StepExecution{},
		&workflows.StepEvidence{},
		&workflows.StepReassignmentHistory{},
		&workflows.ControlRelationship{},
	)
	require.NoError(t, err)
	return db
}

func createOverdueFixture(t *testing.T, db *gorm.DB) (*workflows.WorkflowDefinition, *workflows.WorkflowInstance, *workflows.WorkflowExecution, *workflows.StepExecution) {
	defID := uuid.New()
	defGrace := 1
	def := &workflows.WorkflowDefinition{
		UUIDModel:        relational.UUIDModel{ID: &defID},
		Name:             "Overdue Workflow",
		Version:          "1.0",
		SuggestedCadence: string(workflows.CadenceWeekly),
		GracePeriodDays:  &defGrace,
	}
	require.NoError(t, db.Create(def).Error)

	stepDefID := uuid.New()
	stepDef := &workflows.WorkflowStepDefinition{
		UUIDModel:            relational.UUIDModel{ID: &stepDefID},
		Name:                 "Upload Certificate",
		ResponsibleRole:      "employee",
		WorkflowDefinitionID: &defID,
	}
	require.NoError(t, db.Create(stepDef).Error)

	instanceID := uuid.New()
	sspID := uuid.New()
	instance := &workflows.WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &instanceID},
		Name:                 "Overdue Instance",
		WorkflowDefinitionID: &defID,
		SystemSecurityPlanID: &sspID,
		Cadence:              string(workflows.CadenceWeekly),
		IsActive:             true,
	}
	require.NoError(t, db.Create(instance).Error)

	execID := uuid.New()
	started := time.Now().Add(-72 * time.Hour)
	due := time.Now().Add(-48 * time.Hour)
	exec := &workflows.WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: &execID},
		Status:             workflows.WorkflowStatusInProgress.String(),
		TriggeredBy:        workflows.TriggerManual.String(),
		TriggeredByID:      "user",
		WorkflowInstanceID: &instanceID,
		StartedAt:          &started,
		DueDate:            &due,
	}
	require.NoError(t, db.Create(exec).Error)

	stepID := uuid.New()
	stepDue := time.Now().Add(-24 * time.Hour)
	step := &workflows.StepExecution{
		UUIDModel:                relational.UUIDModel{ID: &stepID},
		WorkflowExecutionID:      &execID,
		WorkflowStepDefinitionID: &stepDefID,
		Status:                   workflows.StepStatusInProgress.String(),
		DueDate:                  &stepDue,
		AssignedToType:           "user",
		AssignedToID:             "u1",
	}
	require.NoError(t, db.Create(step).Error)

	return def, instance, exec, step
}

func TestOverdueService_CheckOverdueTransitions(t *testing.T) {
	db := setupOverdueTestDB(t)
	_, _, exec, step := createOverdueFixture(t, db)

	workflowExecSvc := workflows.NewWorkflowExecutionService(db)
	stepExecSvc := workflows.NewStepExecutionService(db, nil)
	svc := NewOverdueService(db, workflowExecSvc, stepExecSvc, nil, zap.NewNop().Sugar(), 7, nil)

	updatedSteps, err := svc.CheckOverdueSteps(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, updatedSteps)

	updatedExecutions, err := svc.CheckOverdueExecutions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, updatedExecutions)

	var stepAfter workflows.StepExecution
	require.NoError(t, db.First(&stepAfter, step.ID).Error)
	assert.Equal(t, workflows.StepStatusOverdue.String(), stepAfter.Status)
	require.NotNil(t, stepAfter.OverdueAt)

	var execAfter workflows.WorkflowExecution
	require.NoError(t, db.First(&execAfter, exec.ID).Error)
	assert.Equal(t, workflows.WorkflowStatusOverdue.String(), execAfter.Status)
	require.NotNil(t, execAfter.OverdueAt)
}

func TestOverdueService_CheckFailedExecutions_StepOverduePromotesExecutionAndFailsWithZeroGrace(t *testing.T) {
	db := setupOverdueTestDB(t)
	def, instance, exec, step := createOverdueFixture(t, db)

	zero := 0
	require.NoError(t, db.Model(&workflows.WorkflowDefinition{}).
		Where("id = ?", def.ID).
		Update("grace_period_days", zero).Error)
	require.NoError(t, db.Model(&workflows.WorkflowInstance{}).
		Where("id = ?", instance.ID).
		Update("grace_period_days", zero).Error)
	require.NoError(t, db.Model(&workflows.WorkflowExecution{}).
		Where("id = ?", exec.ID).
		Update("due_date", nil).Error)

	workflowExecSvc := workflows.NewWorkflowExecutionService(db)
	stepExecSvc := workflows.NewStepExecutionService(db, nil)
	svc := NewOverdueService(db, workflowExecSvc, stepExecSvc, nil, zap.NewNop().Sugar(), 0, nil)

	updatedSteps, err := svc.CheckOverdueSteps(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, updatedSteps)

	updatedExecutions, err := svc.CheckOverdueExecutions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, updatedExecutions)

	failed, err := svc.CheckFailedExecutions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, failed)

	var execAfter workflows.WorkflowExecution
	require.NoError(t, db.First(&execAfter, exec.ID).Error)
	assert.Equal(t, workflows.WorkflowStatusFailed.String(), execAfter.Status)
	require.NotNil(t, execAfter.FailedAt)

	var stepAfter workflows.StepExecution
	require.NoError(t, db.First(&stepAfter, step.ID).Error)
	assert.Equal(t, workflows.StepStatusFailed.String(), stepAfter.Status)
	require.NotNil(t, stepAfter.FailedAt)
}

func TestOverdueService_CheckFailedExecutions(t *testing.T) {
	db := setupOverdueTestDB(t)
	_, _, exec, step := createOverdueFixture(t, db)

	overdueAt := time.Now().Add(-48 * time.Hour)
	require.NoError(t, db.Model(&workflows.WorkflowExecution{}).
		Where("id = ?", exec.ID).
		Updates(map[string]interface{}{
			"status":     workflows.WorkflowStatusOverdue.String(),
			"overdue_at": overdueAt,
		}).Error)

	require.NoError(t, db.Model(&workflows.StepExecution{}).
		Where("id = ?", step.ID).
		Updates(map[string]interface{}{
			"status":     workflows.StepStatusOverdue.String(),
			"overdue_at": overdueAt,
		}).Error)

	workflowExecSvc := workflows.NewWorkflowExecutionService(db)
	stepExecSvc := workflows.NewStepExecutionService(db, nil)
	svc := NewOverdueService(db, workflowExecSvc, stepExecSvc, nil, zap.NewNop().Sugar(), 1, nil)

	failed, err := svc.CheckFailedExecutions(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, failed)

	var execAfter workflows.WorkflowExecution
	require.NoError(t, db.First(&execAfter, exec.ID).Error)
	assert.Equal(t, workflows.WorkflowStatusFailed.String(), execAfter.Status)
	assert.Equal(t, "overdue - grace period expired", execAfter.FailureReason)
	require.NotNil(t, execAfter.FailedAt)

	var stepAfter workflows.StepExecution
	require.NoError(t, db.First(&stepAfter, step.ID).Error)
	assert.Equal(t, workflows.StepStatusFailed.String(), stepAfter.Status)
	assert.Equal(t, "overdue - grace period expired", stepAfter.FailureReason)
	require.NotNil(t, stepAfter.FailedAt)
}

func TestOverdueService_CheckOverdueSteps_DoesNotMarkBlockedSteps(t *testing.T) {
	db := setupOverdueTestDB(t)
	_, _, _, step := createOverdueFixture(t, db)

	pastDue := time.Now().Add(-24 * time.Hour)
	require.NoError(t, db.Model(&workflows.StepExecution{}).
		Where("id = ?", step.ID).
		Updates(map[string]interface{}{
			"status":   workflows.StepStatusBlocked.String(),
			"due_date": pastDue,
		}).Error)

	workflowExecSvc := workflows.NewWorkflowExecutionService(db)
	stepExecSvc := workflows.NewStepExecutionService(db, nil)
	svc := NewOverdueService(db, workflowExecSvc, stepExecSvc, nil, zap.NewNop().Sugar(), 7, nil)

	updatedSteps, err := svc.CheckOverdueSteps(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, updatedSteps)

	var stepAfter workflows.StepExecution
	require.NoError(t, db.First(&stepAfter, step.ID).Error)
	assert.Equal(t, workflows.StepStatusBlocked.String(), stepAfter.Status)
	assert.Nil(t, stepAfter.OverdueAt)
}
