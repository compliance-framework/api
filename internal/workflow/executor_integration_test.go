//go:build integration

package workflow

import (
	"context"
	"log"
	"os"
	"testing"

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
			EvidenceRequired:     []workflows.EvidenceRequirement{},
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID2},
			Name:                 "Step 2 - Configuration",
			Description:          "Configuration step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     []workflows.EvidenceRequirement{},
			EstimatedDuration:    60,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID3},
			Name:                 "Step 3 - Validation",
			Description:          "Validation step",
			ResponsibleRole:      "validator",
			EvidenceRequired:     []workflows.EvidenceRequirement{},
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

func TestDAGExecutor_Integration_InitializeWorkflow(t *testing.T) {
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
	stepExecService := workflows.NewStepExecutionService(db, nil)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create test workflow
	workflowDef, stepDefs := createTestWorkflow(t, db)
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Initialize workflow
	ctx := context.Background()
	err := executor.InitializeWorkflow(ctx, execution.ID)
	require.NoError(t, err)

	// Verify workflow execution status
	updatedExecution, err := workflowExecService.GetByID(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, "in_progress", updatedExecution.Status)

	// Verify step executions were created
	stepExecutions, err := stepExecService.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)
	assert.Len(t, stepExecutions, 3)

	// Create a map of step executions by definition ID
	stepExecMap := make(map[uuid.UUID]*workflows.StepExecution)
	for i := range stepExecutions {
		stepExecMap[*stepExecutions[i].WorkflowStepDefinitionID] = &stepExecutions[i]
	}

	// Verify step 1 is pending (no dependencies)
	step1Exec := stepExecMap[*stepDefs[0].ID]
	assert.Equal(t, "pending", step1Exec.Status)

	// Verify step 2 is blocked (depends on step 1)
	step2Exec := stepExecMap[*stepDefs[1].ID]
	assert.Equal(t, "blocked", step2Exec.Status)

	// Verify step 3 is blocked (depends on step 2)
	step3Exec := stepExecMap[*stepDefs[2].ID]
	assert.Equal(t, "blocked", step3Exec.Status)
}

func TestDAGExecutor_Integration_ProcessStepCompletion(t *testing.T) {
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
	stepExecService := workflows.NewStepExecutionService(db, nil)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create test workflow
	workflowDef, stepDefs := createTestWorkflow(t, db)
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Initialize workflow
	ctx := context.Background()
	err := executor.InitializeWorkflow(ctx, execution.ID)
	require.NoError(t, err)

	// Get step executions
	stepExecutions, err := stepExecService.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)

	// Create map by definition ID
	stepExecMap := make(map[uuid.UUID]*workflows.StepExecution)
	for i := range stepExecutions {
		stepExecMap[*stepExecutions[i].WorkflowStepDefinitionID] = &stepExecutions[i]
	}

	// Complete step 1 (user action)
	step1Exec := stepExecMap[*stepDefs[0].ID]
	err = stepExecService.UpdateStatus(step1Exec.ID, "completed")
	require.NoError(t, err)

	// Process step completion to unblock dependent steps
	err = executor.ProcessStepCompletion(ctx, step1Exec.ID)
	require.NoError(t, err)

	// Verify step 2 is now unblocked
	step2Exec, err := stepExecService.GetByID(stepExecMap[*stepDefs[1].ID].ID)
	require.NoError(t, err)
	assert.Equal(t, "pending", step2Exec.Status)

	// Step 3 should still be blocked
	step3Exec, err := stepExecService.GetByID(stepExecMap[*stepDefs[2].ID].ID)
	require.NoError(t, err)
	assert.Equal(t, "blocked", step3Exec.Status)
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
	stepExecService := workflows.NewStepExecutionService(db, nil)
	workflowExecService := workflows.NewWorkflowExecutionService(db)
	stepDefService := workflows.NewWorkflowStepDefinitionService(db)

	// Create executor
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	executor := NewDAGExecutor(stepExecService, workflowExecService, stepDefService, logger)

	// Create test workflow
	workflowDef, stepDefs := createTestWorkflow(t, db)
	instance := createTestWorkflowInstance(t, db, workflowDef)
	execution := createTestWorkflowExecution(t, db, instance)

	// Get execution status before initialization
	state, err := executor.GetExecutionStatus(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, *execution.ID, state.WorkflowExecutionID)
	assert.Len(t, state.StepStates, 0) // No step executions yet

	// Initialize workflow
	ctx := context.Background()
	err = executor.InitializeWorkflow(ctx, execution.ID)
	require.NoError(t, err)

	// Get execution status after initialization
	state, err = executor.GetExecutionStatus(execution.ID)
	require.NoError(t, err)
	assert.Len(t, state.StepStates, 3)
	assert.Len(t, state.CompletedSteps, 0)
	assert.Len(t, state.FailedSteps, 0)
	assert.Len(t, state.BlockedSteps, 2) // Steps 2 and 3 are blocked

	// Verify step statuses
	for i, stepDef := range stepDefs {
		stepState, exists := state.StepStates[*stepDef.ID]
		require.True(t, exists, "Step state not found for step %s", stepDef.Name)
		if i == 0 {
			assert.Equal(t, "pending", stepState.Status)
		} else {
			assert.Equal(t, "blocked", stepState.Status)
		}
	}
}

func TestDAGExecutor_Integration_ParallelSteps(t *testing.T) {
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
	stepExecService := workflows.NewStepExecutionService(db, nil)
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
			EvidenceRequired:     []workflows.EvidenceRequirement{},
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID2},
			Name:                 "Parallel Step 2",
			Description:          "Second parallel step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     []workflows.EvidenceRequirement{},
			EstimatedDuration:    30,
			WorkflowDefinitionID: &workflowDefID,
		},
		{
			UUIDModel:            relational.UUIDModel{ID: &stepDefID3},
			Name:                 "Parallel Step 3",
			Description:          "Third parallel step",
			ResponsibleRole:      "admin",
			EvidenceRequired:     []workflows.EvidenceRequirement{},
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

	// Initialize workflow
	ctx := context.Background()
	err = executor.InitializeWorkflow(ctx, execution.ID)
	require.NoError(t, err)

	// Verify step executions - all should be pending (no dependencies)
	stepExecutions, err := stepExecService.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)
	assert.Len(t, stepExecutions, 3)

	// All steps should be pending since they have no dependencies
	for _, stepExec := range stepExecutions {
		assert.Equal(t, "pending", stepExec.Status)
	}
}
