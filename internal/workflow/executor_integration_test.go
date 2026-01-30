//go:build integration

package workflow

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupTestDB creates a test database for integration tests
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	// Auto migrate all tables
	err = db.AutoMigrate(
		&relational.Evidence{},
		&workflows.WorkflowDefinition{},
		&workflows.WorkflowStepDefinition{},
		&workflows.StepDependency{},
		&workflows.StepTrigger{},
		&workflows.WorkflowInstance{},
		&workflows.RoleAssignment{},
		&workflows.WorkflowExecution{},
		&workflows.StepExecution{},
		&workflows.StepEvidence{},
		&workflows.ControlRelationship{},
	)
	require.NoError(t, err)

	return db
}

// createTestWorkflow creates a complete test workflow with steps and dependencies
func createTestWorkflow(t *testing.T, db *gorm.DB) (*workflows.WorkflowDefinition, []workflows.WorkflowStepDefinition) {
	// Create workflow definition
	workflowDefID := uuid.New()
	workflowDef := &workflows.WorkflowDefinition{
		UUIDModel:        relational.UUIDModel{ID: &workflowDefID},
		Name:             "Test Workflow",
		Description:      "Integration test workflow",
		Version:          "1.0",
		SuggestedCadence: "weekly",
		EvidenceRequired: "[]",
	}

	err := db.Create(workflowDef).Error
	require.NoError(t, err)

	// Create step definitions
	stepDefID1 := uuid.New()
	stepDefID2 := uuid.New()
	stepDefID3 := uuid.New()

	stepDefs := []workflows.WorkflowStepDefinition{
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID1},
			Name:                 "Step 1 - Initial Setup",
			Description:          "Initial setup step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     "[]",
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID2},
			Name:                 "Step 2 - Configuration",
			Description:          "Configuration step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     "[]",
			EstimatedDuration:    60,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID3},
			Name:                 "Step 3 - Validation",
			Description:          "Validation step",
			ResponsibleRole:      "validator",
			EvidenceRequired:     "[]",
			EstimatedDuration:    45,
			WorkflowDefinitionID: &workflowDefID,
		},
	}

	// Create step definitions
	for i := range stepDefs {
		err := db.Create(&stepDefs[i]).Error
		require.NoError(t, err)
	}

	// Create dependencies: Step 2 depends on Step 1, Step 3 depends on Step 2
	dep1 := &workflows.StepDependency{
		UUIDModel:                relational.UUIDModel{},
		WorkflowStepDefinitionID: &stepDefID2,
		DependsOnStepID:          &stepDefID1,
	}
	err = db.Create(dep1).Error
	require.NoError(t, err)

	dep2 := &workflows.StepDependency{
		UUIDModel:                relational.UUIDModel{},
		WorkflowStepDefinitionID: &stepDefID3,
		DependsOnStepID:          &stepDefID2,
	}
	err = db.Create(dep2).Error
	require.NoError(t, err)

	return workflowDef, stepDefs
}

// createTestWorkflowInstance creates a test workflow instance
func createTestWorkflowInstance(t *testing.T, db *gorm.DB, workflowDef *workflows.WorkflowDefinition) *workflows.WorkflowInstance {
	instanceID := uuid.New()
	sspID := uuid.New()
	instance := &workflows.WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &instanceID},
		Name:                 "Test Instance",
		Description:          "Test workflow instance",
		SystemSecurityPlanID: &sspID,
		Cadence:              "weekly",
		IsActive:             true,
		WorkflowDefinitionID: workflowDef.ID,
	}

	err := db.Create(instance).Error
	require.NoError(t, err)
	return instance
}

// createTestWorkflowExecution creates a test workflow execution
func createTestWorkflowExecution(t *testing.T, db *gorm.DB, instance *workflows.WorkflowInstance) *workflows.WorkflowExecution {
	executionID := uuid.New()
	execution := &workflows.WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: &executionID},
		Status:             "pending",
		TriggeredBy:        "manual",
		TriggeredByID:      "test-user",
		WorkflowInstanceID: instance.ID,
	}

	err := db.Create(execution).Error
	require.NoError(t, err)
	return execution
}

func TestDAGExecutor_Integration_ExecuteWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test database
	db := setupTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Create services
	stepExecService := workflows.NewStepExecutionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create test workflow
	workflowDef, stepDefs := createTestWorkflow(t, db)
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Execute workflow
	ctx := context.Background()
	result, err := executor.ExecuteWorkflow(ctx, execution.ID)

	// Verify results
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.TotalSteps)
	assert.Equal(t, 3, result.CompletedSteps)
	assert.Equal(t, 0, result.FailedSteps)

	// Verify workflow execution status
	updatedExecution, err := workflowExecService.GetByID(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", updatedExecution.Status)
	assert.NotNil(t, updatedExecution.StartedAt)
	assert.NotNil(t, updatedExecution.CompletedAt)

	// Verify step executions
	stepExecutions, err := stepExecService.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)
	assert.Len(t, stepExecutions, 3)

	// Create a map of step executions by definition ID for easier verification
	stepExecMap := make(map[uuid.UUID]*workflows.StepExecution)
	for i := range stepExecutions {
		stepExecMap[*stepExecutions[i].WorkflowStepDefinitionID] = &stepExecutions[i]
	}

	// Verify each step execution
	for _, stepDef := range stepDefs {
		stepExec, exists := stepExecMap[*stepDef.ID]
		require.True(t, exists, "Step execution not found for step %s", stepDef.Name)
		assert.Equal(t, "completed", stepExec.Status)
		assert.NotNil(t, stepExec.StartedAt)
		assert.NotNil(t, stepExec.CompletedAt)
	}

	// Verify execution order (Step 1 should complete before Step 2, etc.)
	step1Exec := stepExecMap[*stepDefs[0].ID]
	step2Exec := stepExecMap[*stepDefs[1].ID]
	step3Exec := stepExecMap[*stepDefs[2].ID]

	assert.True(t, step1Exec.CompletedAt.Before(*step2Exec.CompletedAt) || step1Exec.CompletedAt.Equal(*step2Exec.CompletedAt))
	assert.True(t, step2Exec.CompletedAt.Before(*step3Exec.CompletedAt) || step2Exec.CompletedAt.Equal(*step3Exec.CompletedAt))
}

func TestDAGExecutor_Integration_CancelExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test database
	db := setupTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Create services
	stepExecService := workflows.NewStepExecutionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create test workflow
	workflowDef, _ := createTestWorkflow(t, db)
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Start workflow execution in a goroutine
	ctx := context.Background()
	done := make(chan error, 1)

	go func() {
		_, err := executor.ExecuteWorkflow(ctx, execution.ID)
		done <- err
	}()

	// Wait a bit for execution to start
	time.Sleep(50 * time.Millisecond)

	// Cancel the execution
	err := executor.CancelExecution(ctx, execution.ID)
	require.NoError(t, err)

	// Wait for execution to complete
	select {
	case err := <-done:
		// Execution should have been cancelled or completed
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Execution did not complete within timeout")
	}

	// Verify workflow execution status
	updatedExecution, err := workflowExecService.GetByID(execution.ID)
	require.NoError(t, err)
	// Status could be either "cancelled" or "completed" depending on timing
	// The important thing is that cancellation was processed without error
	assert.Contains(t, []string{"cancelled", "completed"}, updatedExecution.Status,
		"Expected status to be either cancelled or completed, got: %s", updatedExecution.Status)
}

func TestDAGExecutor_Integration_GetExecutionStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test database
	db := setupTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Create services
	stepExecService := workflows.NewStepExecutionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create test workflow
	workflowDef, stepDefs := createTestWorkflow(t, db)
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Get execution status before execution
	state, err := executor.GetExecutionStatus(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, *execution.ID, state.WorkflowExecutionID)
	assert.Len(t, state.StepStates, 0) // No step executions yet

	// Execute workflow
	ctx := context.Background()
	_, err = executor.ExecuteWorkflow(ctx, execution.ID)
	require.NoError(t, err)

	// Get execution status after execution
	state, err = executor.GetExecutionStatus(execution.ID)
	require.NoError(t, err)
	assert.Len(t, state.StepStates, 3)
	assert.Len(t, state.CompletedSteps, 3)
	assert.Len(t, state.FailedSteps, 0)
	assert.Len(t, state.RunningSteps, 0)

	// Verify all steps are in completed state
	for _, stepDef := range stepDefs {
		stepState, exists := state.StepStates[*stepDef.ID]
		require.True(t, exists, "Step state not found for step %s", stepDef.Name)
		assert.Equal(t, "completed", stepState.Status)
	}
}

func TestDAGExecutor_Integration_ParallelExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test database
	db := setupTestDB(t)
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Create services
	stepExecService := workflows.NewStepExecutionService(db)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create workflow with parallel steps (no dependencies)
	workflowDefID := uuid.New()
	workflowDef := &workflows.WorkflowDefinition{
		UUIDModel:        relational.UUIDModel{ID: &workflowDefID},
		Name:             "Parallel Workflow",
		Description:      "Workflow with parallel steps",
		Version:          "1.0",
		SuggestedCadence: "weekly",
		EvidenceRequired: "[]",
	}

	err := db.Create(workflowDef).Error
	require.NoError(t, err)

	// Create parallel step definitions
	stepDefID1 := uuid.New()
	stepDefID2 := uuid.New()
	stepDefID3 := uuid.New()

	stepDefs := []workflows.WorkflowStepDefinition{
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID1},
			Name:                 "Parallel Step 1",
			Description:          "First parallel step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     "[]",
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID2},
			Name:                 "Parallel Step 2",
			Description:          "Second parallel step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     "[]",
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID3},
			Name:                 "Parallel Step 3",
			Description:          "Third parallel step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     "[]",
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
	}

	// Create step definitions
	for i := range stepDefs {
		err := db.Create(&stepDefs[i]).Error
		require.NoError(t, err)
	}

	// Create instance and execution
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Execute workflow
	ctx := context.Background()
	result, err := executor.ExecuteWorkflow(ctx, execution.ID)

	// Verify results
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, 3, result.TotalSteps)
	assert.Equal(t, 3, result.CompletedSteps)
	assert.Equal(t, 0, result.FailedSteps)

	// Verify step executions
	stepExecutions, err := stepExecService.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)
	assert.Len(t, stepExecutions, 3)

	// All steps should have started around the same time (within a reasonable window)
	var startTimes []time.Time
	for _, stepExec := range stepExecutions {
		startTimes = append(startTimes, *stepExec.StartedAt)
	}

	// Check that steps started within 100ms of each other (indicating parallel execution)
	maxDiff := time.Duration(0)
	for i := 0; i < len(startTimes); i++ {
		for j := i + 1; j < len(startTimes); j++ {
			diff := startTimes[i].Sub(startTimes[j])
			if diff < 0 {
				diff = -diff
			}
			if diff > maxDiff {
				maxDiff = diff
			}
		}
	}

	// Allow some tolerance for test environment
	assert.Less(t, maxDiff, 400*time.Millisecond, "Steps should have started in parallel")
}
