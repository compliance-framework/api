package workflows

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStepExecutionService_Create tests the Create method
func TestStepExecutionService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Test successful creation
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	err := service.Create(stepExecution)
	require.NoError(t, err)
	require.NotNil(t, stepExecution.ID)
	assert.Equal(t, "pending", stepExecution.Status) // Default status should be set

	// Verify in database
	var found StepExecution
	err = db.First(&found, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, execution.ID, found.WorkflowExecutionID)

	// Test with nil step execution
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step execution cannot be nil")

	// Test with invalid step execution (missing required fields)
	invalidStepExec := &StepExecution{}
	err = service.Create(invalidStepExec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow execution ID is required")
}

// TestStepExecutionService_GetByID tests the GetByID method
func TestStepExecutionService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test successful retrieval
	retrieved, err := service.GetByID(stepExecution.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, stepExecution.WorkflowExecutionID, retrieved.WorkflowExecutionID)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "step execution with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestStepExecutionService_GetByWorkflowExecutionID tests the GetByWorkflowExecutionID method
func TestStepExecutionService_GetByWorkflowExecutionID(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create multiple step executions
	stepExec1 := createTestStepExecution(execution.ID, stepDef.ID)
	stepExec2 := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExec1).Error)
	require.NoError(t, db.Create(stepExec2).Error)

	// Test retrieval
	retrieved, err := service.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved, 2)

	// Test with non-existent execution ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByWorkflowExecutionID(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, retrieved, 0)
}

// TestStepExecutionService_Update tests the Update method
func TestStepExecutionService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test successful update
	updates := &StepExecution{
		UUIDModel:     relational.UUIDModel{ID: stepExecution.ID},
		FailureReason: "Updated failure reason",
	}
	err := service.Update(stepExecution.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated StepExecution
	err = db.First(&updated, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "Updated failure reason", updated.FailureReason)

	// Test with nil updates
	err = service.Update(stepExecution.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	updatesWithNonExistentID := &StepExecution{
		UUIDModel:     relational.UUIDModel{ID: &nonExistentID},
		FailureReason: "Updated failure reason",
	}
	err = service.Update(&nonExistentID, updatesWithNonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step execution with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestStepExecutionService_UpdateStatus tests the UpdateStatus method
func TestStepExecutionService_UpdateStatus(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test updating to in_progress
	err := service.UpdateStatus(context.Background(), stepExecution.ID, "in_progress")
	require.NoError(t, err)

	var updated StepExecution
	err = db.First(&updated, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "in_progress", updated.Status)
	assert.NotNil(t, updated.StartedAt)

	// Test updating to completed
	err = service.UpdateStatus(context.Background(), stepExecution.ID, "completed")
	require.NoError(t, err)

	err = db.First(&updated, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "completed", updated.Status)
	assert.NotNil(t, updated.CompletedAt)

	// Test updating to failed
	err = service.UpdateStatus(context.Background(), stepExecution.ID, "failed")
	require.NoError(t, err)

	err = db.First(&updated, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "failed", updated.Status)
	assert.NotNil(t, updated.FailedAt)

	// Test with invalid status
	err = service.UpdateStatus(context.Background(), stepExecution.ID, "invalid_status")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status")
}

// TestStepExecutionService_Start tests the Start method
func TestStepExecutionService_Start(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test starting
	err := service.Start(stepExecution.ID)
	require.NoError(t, err)

	// Verify start
	var started StepExecution
	err = db.First(&started, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "in_progress", started.Status)
	assert.NotNil(t, started.StartedAt)
}

// TestStepExecutionService_Complete tests the Complete method
func TestStepExecutionService_Complete(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test completion
	err := service.Complete(stepExecution.ID)
	require.NoError(t, err)

	// Verify completion
	var completed StepExecution
	err = db.First(&completed, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "completed", completed.Status)
	assert.NotNil(t, completed.CompletedAt)
}

// TestStepExecutionService_Fail tests the Fail method
func TestStepExecutionService_Fail(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test failure
	reason := "Test failure reason"
	err := service.Fail(stepExecution.ID, reason)
	require.NoError(t, err)

	// Verify failure
	var failed StepExecution
	err = db.First(&failed, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "failed", failed.Status)
	assert.NotNil(t, failed.FailedAt)
	assert.Equal(t, reason, failed.FailureReason)
}

// TestStepExecutionService_Block tests the Block method
func TestStepExecutionService_Block(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test blocking
	err := service.Block(stepExecution.ID)
	require.NoError(t, err)

	// Verify block
	var blocked StepExecution
	err = db.First(&blocked, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "blocked", blocked.Status)
}

// TestStepExecutionService_Unblock tests the Unblock method
func TestStepExecutionService_Unblock(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution and block it
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	stepExecution.Status = "blocked"
	require.NoError(t, db.Create(stepExecution).Error)

	// Test unblocking
	err := service.Unblock(stepExecution.ID)
	require.NoError(t, err)

	// Verify unblock
	var unblocked StepExecution
	err = db.First(&unblocked, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "pending", unblocked.Status)
}

// TestStepExecutionService_AssignTo tests the AssignTo method
func TestStepExecutionService_AssignTo(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create a test step execution
	stepExecution := createTestStepExecution(execution.ID, stepDef.ID)
	require.NoError(t, db.Create(stepExecution).Error)

	// Test assignment
	assignedToType := "user"
	assignedToID := uuid.New().String()
	err := service.AssignTo(stepExecution.ID, assignedToType, assignedToID)
	require.NoError(t, err)

	// Verify assignment
	var assigned StepExecution
	err = db.First(&assigned, stepExecution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, assignedToType, assigned.AssignedToType)
	assert.Equal(t, assignedToID, assigned.AssignedToID)
	assert.NotNil(t, assigned.AssignedAt)
}

// TestStepExecutionService_GetPendingSteps tests the GetPendingSteps method
func TestStepExecutionService_GetPendingSteps(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create step executions with different statuses
	pendingStep1 := createTestStepExecution(execution.ID, stepDef.ID)
	pendingStep2 := createTestStepExecution(execution.ID, stepDef.ID)
	inProgressStep := createTestStepExecution(execution.ID, stepDef.ID)
	inProgressStep.Status = "in_progress"

	require.NoError(t, db.Create(pendingStep1).Error)
	require.NoError(t, db.Create(pendingStep2).Error)
	require.NoError(t, db.Create(inProgressStep).Error)

	// Test retrieval
	pendingSteps, err := service.GetPendingSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, pendingSteps, 2)

	// Test with non-existent execution ID
	nonExistentID := uuid.New()
	pendingSteps, err = service.GetPendingSteps(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, pendingSteps, 0)
}

// TestStepExecutionService_GetBlockedSteps tests the GetBlockedSteps method
func TestStepExecutionService_GetBlockedSteps(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create step executions with different statuses
	blockedStep1 := createTestStepExecution(execution.ID, stepDef.ID)
	blockedStep1.Status = "blocked"
	blockedStep2 := createTestStepExecution(execution.ID, stepDef.ID)
	blockedStep2.Status = "blocked"
	pendingStep := createTestStepExecution(execution.ID, stepDef.ID)

	require.NoError(t, db.Create(blockedStep1).Error)
	require.NoError(t, db.Create(blockedStep2).Error)
	require.NoError(t, db.Create(pendingStep).Error)

	// Test retrieval
	blockedSteps, err := service.GetBlockedSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, blockedSteps, 2)

	// Test with non-existent execution ID
	nonExistentID := uuid.New()
	blockedSteps, err = service.GetBlockedSteps(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, blockedSteps, 0)
}

// TestStepExecutionService_GetCompletedSteps tests the GetCompletedSteps method
func TestStepExecutionService_GetCompletedSteps(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create step executions with different statuses
	completedStep1 := createTestStepExecution(execution.ID, stepDef.ID)
	completedStep1.Status = "completed"
	completedStep2 := createTestStepExecution(execution.ID, stepDef.ID)
	completedStep2.Status = "completed"
	pendingStep := createTestStepExecution(execution.ID, stepDef.ID)

	require.NoError(t, db.Create(completedStep1).Error)
	require.NoError(t, db.Create(completedStep2).Error)
	require.NoError(t, db.Create(pendingStep).Error)

	// Test retrieval
	completedSteps, err := service.GetCompletedSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, completedSteps, 2)

	// Test with non-existent execution ID
	nonExistentID := uuid.New()
	completedSteps, err = service.GetCompletedSteps(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, completedSteps, 0)
}

// TestStepExecutionService_GetAssignedSteps tests the GetAssignedSteps method
func TestStepExecutionService_GetAssignedSteps(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create step executions with different assignments
	assignedStep1 := createTestStepExecution(execution.ID, stepDef.ID)
	assignedStep1.AssignedToType = "user"
	assignedStep1.AssignedToID = "user123"

	assignedStep2 := createTestStepExecution(execution.ID, stepDef.ID)
	assignedStep2.AssignedToType = "user"
	assignedStep2.AssignedToID = "user123"

	unassignedStep := createTestStepExecution(execution.ID, stepDef.ID)

	require.NoError(t, db.Create(assignedStep1).Error)
	require.NoError(t, db.Create(assignedStep2).Error)
	require.NoError(t, db.Create(unassignedStep).Error)

	// Test retrieval
	assignedSteps, err := service.GetAssignedSteps("user", "user123")
	require.NoError(t, err)
	assert.Len(t, assignedSteps, 2)

	// Test with no assignments
	assignedSteps, err = service.GetAssignedSteps("user", "nonexistent")
	require.NoError(t, err)
	assert.Len(t, assignedSteps, 0)
}

// TestStepExecutionService_ValidateStepExecution tests the ValidateStepExecution method
func TestStepExecutionService_ValidateStepExecution(t *testing.T) {
	// Test valid step execution
	id1 := uuid.New()
	id2 := uuid.New()
	validStepExec := createTestStepExecution(&id1, &id2)
	err := ValidateStepExecution(validStepExec)
	assert.NoError(t, err)

	// Test nil step execution
	err = ValidateStepExecution(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step execution cannot be nil")

	// Test missing workflow execution ID
	id := uuid.New()
	invalidStepExec := createTestStepExecution(nil, &id)
	err = ValidateStepExecution(invalidStepExec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow execution ID is required")

	// Test missing workflow step definition ID
	invalidStepExec = createTestStepExecution(&id, nil)
	err = ValidateStepExecution(invalidStepExec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step definition ID is required")
}

// TestStepExecutionService_CanUnblock tests the CanUnblock method
func TestStepExecutionService_CanUnblock(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	// Create step definitions
	stepDef1 := createTestWorkflowStepDefinition(workflowDef.ID)
	stepDef1.Name = "Step 1"
	require.NoError(t, db.Create(stepDef1).Error)

	stepDef2 := createTestWorkflowStepDefinition(workflowDef.ID)
	stepDef2.Name = "Step 2"
	require.NoError(t, db.Create(stepDef2).Error)

	// Create step executions
	stepExec1 := createTestStepExecution(execution.ID, stepDef1.ID)
	stepExec1.Status = "completed"
	require.NoError(t, db.Create(stepExec1).Error)

	stepExec2 := createTestStepExecution(execution.ID, stepDef2.ID)
	stepExec2.Status = "blocked"
	require.NoError(t, db.Create(stepExec2).Error)

	// Test can unblock when no dependencies
	canUnblock, err := service.CanUnblock(stepExec2.ID)
	require.NoError(t, err)
	assert.True(t, canUnblock)

	// Test with dependencies (create dependency relationship)
	// This would require setting up the DependsOn relationship in WorkflowStepDefinition
	// For now, we'll test the basic functionality
}

// TestStepExecutionService_GetUnblockableSteps tests the GetUnblockableSteps method
func TestStepExecutionService_GetUnblockableSteps(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	stepDef := createTestWorkflowStepDefinition(workflowDef.ID)
	require.NoError(t, db.Create(stepDef).Error)

	// Create blocked step executions
	blockedStep1 := createTestStepExecution(execution.ID, stepDef.ID)
	blockedStep1.Status = "blocked"
	blockedStep2 := createTestStepExecution(execution.ID, stepDef.ID)
	blockedStep2.Status = "blocked"

	require.NoError(t, db.Create(blockedStep1).Error)
	require.NoError(t, db.Create(blockedStep2).Error)

	// Test retrieval
	unblockableSteps, err := service.GetUnblockableSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, unblockableSteps, 2) // Both should be unblockable since they have no dependencies

	// Test with no blocked steps
	nonExistentID := uuid.New()
	unblockableSteps, err = service.GetUnblockableSteps(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, unblockableSteps, 0)
}

// TestStepExecutionService_Integration tests integration scenarios
func TestStepExecutionService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewStepExecutionService(db, nil)

	// Create complete test data
	workflowDef := createTestWorkflowDefinition()
	workflowDef.Name = "Integration Test Workflow"
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	instance.Name = "Integration Test Instance"
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	execution.Status = "in_progress"
	require.NoError(t, db.Create(execution).Error)

	// Create multiple step definitions
	stepDef1 := createTestWorkflowStepDefinition(workflowDef.ID)
	stepDef1.Name = "Step 1: Data Collection"
	stepDef1.ResponsibleRole = "data_analyst"
	require.NoError(t, db.Create(stepDef1).Error)

	stepDef2 := createTestWorkflowStepDefinition(workflowDef.ID)
	stepDef2.Name = "Step 2: Analysis"
	stepDef2.ResponsibleRole = "analyst"
	require.NoError(t, db.Create(stepDef2).Error)

	// Create step executions
	stepExec1 := createTestStepExecution(execution.ID, stepDef1.ID)
	err := service.Create(stepExec1)
	require.NoError(t, err)

	stepExec2 := createTestStepExecution(execution.ID, stepDef2.ID)
	err = service.Create(stepExec2)
	require.NoError(t, err)

	// Test full lifecycle
	// Start first step
	require.NoError(t, service.Start(stepExec1.ID))

	// Complete first step
	require.NoError(t, service.Complete(stepExec1.ID))

	// Assign second step
	require.NoError(t, service.AssignTo(stepExec2.ID, "user", "analyst123"))

	// Start second step
	require.NoError(t, service.Start(stepExec2.ID))

	// Verify all step executions
	allSteps, err := service.GetByWorkflowExecutionID(execution.ID)
	require.NoError(t, err)
	assert.Len(t, allSteps, 2)

	// Verify step statuses
	pendingSteps, err := service.GetPendingSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, pendingSteps, 0)

	completedSteps, err := service.GetCompletedSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, completedSteps, 1)

	// Test assignment retrieval
	assignedSteps, err := service.GetAssignedSteps("user", "analyst123")
	require.NoError(t, err)
	assert.Len(t, assignedSteps, 1)
	assert.Equal(t, "in_progress", assignedSteps[0].Status)

	// Complete second step
	require.NoError(t, service.Complete(stepExec2.ID))

	// Verify all steps are completed
	completedSteps, err = service.GetCompletedSteps(execution.ID)
	require.NoError(t, err)
	assert.Len(t, completedSteps, 2)
}
