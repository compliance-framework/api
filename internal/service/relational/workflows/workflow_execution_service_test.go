package workflows

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWorkflowExecutionService_Create tests the Create method
func TestWorkflowExecutionService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test successful creation
	execution := createTestWorkflowExecution(instance.ID)
	err := service.Create(execution)
	require.NoError(t, err)
	require.NotNil(t, execution.ID)
	assert.Equal(t, "pending", execution.Status) // Default status should be set

	// Verify in database
	var found WorkflowExecution
	err = db.First(&found, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, execution.Status, found.Status)

	// Test with nil execution
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow execution cannot be nil")

	// Test with nil workflow instance ID
	invalidExecution := createTestWorkflowExecution(nil)
	err = service.Create(invalidExecution)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance ID is required")

	// Test with invalid trigger type
	invalidExecution = createTestWorkflowExecution(instance.ID)
	invalidExecution.TriggeredBy = "invalid"
	err = service.Create(invalidExecution)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid triggered by")
}

// TestWorkflowExecutionService_GetByID tests the GetByID method
func TestWorkflowExecutionService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test successful retrieval
	retrieved, err := service.GetByID(execution.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, execution.Status, retrieved.Status)
	assert.NotNil(t, retrieved.WorkflowInstance)
	assert.NotNil(t, retrieved.WorkflowInstance.WorkflowDefinition)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "workflow execution with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowExecutionService_GetByID_PopulatesExecutionStreamUUID tests that GetByID computes
// and populates ExecutionStreamUUID so callers can link to the evidence stream without extra queries.
// BCH-1155: terminal evidence is created in a stream but there was no navigable link to it.
func TestWorkflowExecutionService_GetByID_PopulatesExecutionStreamUUID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	execution := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution).Error)

	retrieved, err := service.GetByID(execution.ID)
	require.NoError(t, err)

	// ExecutionStreamUUID must be populated and deterministic
	require.NotNil(t, retrieved.ExecutionStreamUUID)
	assert.NotEqual(t, uuid.Nil, *retrieved.ExecutionStreamUUID)

	// Calling again should produce the same UUID
	retrieved2, err := service.GetByID(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, *retrieved.ExecutionStreamUUID, *retrieved2.ExecutionStreamUUID)
}

// TestWorkflowExecutionService_GetByWorkflowInstanceID tests the GetByWorkflowInstanceID method
func TestWorkflowExecutionService_GetByWorkflowInstanceID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Create multiple executions for the instance
	executions := []*WorkflowExecution{
		createTestWorkflowExecution(instance.ID),
		createTestWorkflowExecution(instance.ID),
		createTestWorkflowExecution(instance.ID),
	}

	for i, execution := range executions {
		execution.Status = "test_status_" + string(rune('A'+i))
		if err := db.Create(execution).Error; err != nil {
			t.Fatalf("Failed to create test workflow execution %d: %v", i, err)
		}
	}

	// Test retrieval
	retrieved, err := service.GetByWorkflowInstanceID(instance.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved, 3)

	// Verify ordering (should be DESC by created_at)
	for i := 0; i < len(retrieved)-1; i++ {
		assert.True(t, retrieved[i].CreatedAt.After(retrieved[i+1].CreatedAt) ||
			retrieved[i].CreatedAt.Equal(retrieved[i+1].CreatedAt))
	}

	// Test with non-existent workflow instance ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByWorkflowInstanceID(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, retrieved, 0)
}

// TestWorkflowExecutionService_GetAll tests the GetAll method
func TestWorkflowExecutionService_GetAll(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Create multiple executions with different statuses
	executions := []*WorkflowExecution{
		createTestWorkflowExecution(instance.ID),
		createTestWorkflowExecution(instance.ID),
		createTestWorkflowExecution(instance.ID),
	}

	executions[0].Status = "pending"
	executions[1].Status = "in_progress"
	executions[2].Status = "completed"

	for i, execution := range executions {
		execution.TriggeredBy = "manual"
		if i == 1 {
			execution.TriggeredBy = "scheduled"
		}
		if err := db.Create(execution).Error; err != nil {
			t.Fatalf("Failed to create test workflow execution %d: %v", i, err)
		}
	}

	// Test getting all without filters
	retrieved, total, err := service.GetAll(10, 0, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 3)

	// Test pagination
	retrieved, total, err = service.GetAll(2, 1, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 2)

	// Test with status filter
	filters := map[string]interface{}{
		"status": "in_progress",
	}
	retrieved, total, err = service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, retrieved, 1)
	assert.Equal(t, "in_progress", retrieved[0].Status)

	// Test with triggered_by filter
	filters = map[string]interface{}{
		"triggered_by": "scheduled",
	}
	retrieved, total, err = service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, retrieved, 1)
	assert.Equal(t, "scheduled", retrieved[0].TriggeredBy)

	// Test with workflow instance filter
	filters = map[string]interface{}{
		"workflow_instance_id": instance.ID,
	}
	retrieved, total, err = service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 3)
}

// TestWorkflowExecutionService_Update tests the Update method
func TestWorkflowExecutionService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test successful update
	updates := &WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: execution.ID},
		WorkflowInstanceID: execution.WorkflowInstanceID,
		Status:             "in_progress",
		TriggeredBy:        "scheduled",
		TriggeredByID:      "system_user",
	}
	err := service.Update(execution.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated WorkflowExecution
	err = db.First(&updated, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "in_progress", updated.Status)
	assert.Equal(t, "scheduled", updated.TriggeredBy)

	// Test with nil updates
	err = service.Update(execution.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	updatesWithNonExistentID := &WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: &nonExistentID},
		WorkflowInstanceID: instance.ID,
		Status:             "in_progress",
	}
	err = service.Update(&nonExistentID, updatesWithNonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow execution with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowExecutionService_UpdateStatus tests the UpdateStatus method
func TestWorkflowExecutionService_UpdateStatus(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test updating to in_progress
	err := service.UpdateStatus(context.Background(), execution.ID, "in_progress")
	require.NoError(t, err)

	// Verify update and timestamp
	var updated WorkflowExecution
	err = db.First(&updated, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "in_progress", updated.Status)
	assert.NotNil(t, updated.StartedAt)

	// Test updating to completed
	err = service.UpdateStatus(context.Background(), execution.ID, "completed")
	require.NoError(t, err)

	err = db.First(&updated, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "completed", updated.Status)
	assert.NotNil(t, updated.CompletedAt)

	// Test updating to failed
	err = service.UpdateStatus(context.Background(), execution.ID, "failed")
	require.NoError(t, err)

	err = db.First(&updated, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "failed", updated.Status)
	assert.NotNil(t, updated.FailedAt)

	// Test with invalid status
	err = service.UpdateStatus(context.Background(), execution.ID, "invalid_status")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status")

	// Test overdue transition
	execution2 := createTestWorkflowExecution(instance.ID)
	require.NoError(t, db.Create(execution2).Error)
	err = service.UpdateStatus(context.Background(), execution2.ID, "overdue")
	require.NoError(t, err)
	var updatedOverdue WorkflowExecution
	err = db.First(&updatedOverdue, execution2.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "overdue", updatedOverdue.Status)
	assert.NotNil(t, updatedOverdue.OverdueAt)

	// Test overdue -> completed transition
	err = service.UpdateStatus(context.Background(), execution2.ID, "completed")
	require.NoError(t, err)
	err = db.First(&updatedOverdue, execution2.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "completed", updatedOverdue.Status)
	assert.NotNil(t, updatedOverdue.CompletedAt)
}

// TestWorkflowExecutionService_Start tests the Start method
func TestWorkflowExecutionService_Start(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test starting execution
	err := service.Start(execution.ID)
	require.NoError(t, err)

	// Verify update
	var started WorkflowExecution
	err = db.First(&started, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "in_progress", started.Status)
	assert.NotNil(t, started.StartedAt)
}

// TestWorkflowExecutionService_Complete tests the Complete method
func TestWorkflowExecutionService_Complete(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test completing execution
	err := service.Complete(execution.ID)
	require.NoError(t, err)

	// Verify update
	var completed WorkflowExecution
	err = db.First(&completed, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "completed", completed.Status)
	assert.NotNil(t, completed.CompletedAt)
}

// TestWorkflowExecutionService_Fail tests the Fail method
func TestWorkflowExecutionService_Fail(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test failing execution
	reason := "Test failure reason"
	err := service.Fail(execution.ID, reason)
	require.NoError(t, err)

	// Verify update
	var failed WorkflowExecution
	err = db.First(&failed, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "failed", failed.Status)
	assert.Equal(t, reason, failed.FailureReason)
	assert.NotNil(t, failed.FailedAt)
}

// TestWorkflowExecutionService_Cancel tests the Cancel method
func TestWorkflowExecutionService_Cancel(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Test cancelling execution
	err := service.Cancel(execution.ID)
	require.NoError(t, err)

	// Verify update
	var cancelled WorkflowExecution
	err = db.First(&cancelled, execution.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "cancelled", cancelled.Status)
}

// TestWorkflowExecutionService_GetActiveExecutions tests the GetActiveExecutions method
func TestWorkflowExecutionService_GetActiveExecutions(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Create executions with different statuses
	activeExecution := createTestWorkflowExecution(instance.ID)
	activeExecution.Status = "in_progress"

	completedExecution := createTestWorkflowExecution(instance.ID)
	completedExecution.Status = "completed"

	pendingExecution := createTestWorkflowExecution(instance.ID)
	pendingExecution.Status = "pending"

	if err := db.Create(activeExecution).Error; err != nil {
		t.Fatalf("Failed to create active execution: %v", err)
	}
	if err := db.Create(completedExecution).Error; err != nil {
		t.Fatalf("Failed to create completed execution: %v", err)
	}
	if err := db.Create(pendingExecution).Error; err != nil {
		t.Fatalf("Failed to create pending execution: %v", err)
	}

	// Test getting active executions
	activeExecutions, err := service.GetActiveExecutions()
	require.NoError(t, err)
	assert.Len(t, activeExecutions, 1)
	assert.Equal(t, activeExecution.ID, activeExecutions[0].ID)
	assert.Equal(t, "in_progress", activeExecutions[0].Status)
}

// TestWorkflowExecutionService_GetRecentExecutions tests the GetRecentExecutions method
func TestWorkflowExecutionService_GetRecentExecutions(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Create executions at different times
	oldTime := time.Now().Add(-2 * time.Hour)
	recentTime := time.Now().Add(-30 * time.Minute)

	oldExecution := createTestWorkflowExecution(instance.ID)
	recentExecution := createTestWorkflowExecution(instance.ID)

	if err := db.Create(oldExecution).Error; err != nil {
		t.Fatalf("Failed to create old execution: %v", err)
	}

	// Update the created_at time for old execution
	if err := db.Model(oldExecution).Update("created_at", oldTime).Error; err != nil {
		t.Fatalf("Failed to update old execution time: %v", err)
	}

	time.Sleep(10 * time.Millisecond) // Ensure different creation times

	if err := db.Create(recentExecution).Error; err != nil {
		t.Fatalf("Failed to create recent execution: %v", err)
	}

	// Update the created_at time for recent execution
	if err := db.Model(recentExecution).Update("created_at", recentTime).Error; err != nil {
		t.Fatalf("Failed to update recent execution time: %v", err)
	}

	// Test getting recent executions (since 1 hour ago)
	since := time.Now().Add(-1 * time.Hour)
	recentExecutions, err := service.GetRecentExecutions(since, 10)
	require.NoError(t, err)
	assert.Len(t, recentExecutions, 1)
	assert.Equal(t, recentExecution.ID, recentExecutions[0].ID)

	// Test with limit
	recentExecutions, err = service.GetRecentExecutions(since, 0)
	require.NoError(t, err)
	assert.Len(t, recentExecutions, 0)
}

// TestWorkflowExecutionService_ValidateExecution tests the ValidateExecution method
func TestWorkflowExecutionService_ValidateExecution(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Test valid execution
	testUUID := uuid.New()
	validExecution := createTestWorkflowExecution(&testUUID)
	err := service.ValidateExecution(validExecution)
	assert.NoError(t, err)

	// Test nil execution
	err = service.ValidateExecution(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow execution cannot be nil")

	// Test with nil workflow instance ID
	testUUID2 := uuid.New()
	invalidExecution := createTestWorkflowExecution(&testUUID2)
	invalidExecution.WorkflowInstanceID = nil
	err = service.ValidateExecution(invalidExecution)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance ID is required")

	// Test with invalid trigger type
	invalidExecution.WorkflowInstanceID = &testUUID2
	invalidExecution.TriggeredBy = "invalid"
	err = service.ValidateExecution(invalidExecution)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid triggered by")
}

// TestWorkflowExecutionService_GetExecutionProgress tests the GetExecutionProgress method
func TestWorkflowExecutionService_GetExecutionProgress(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create workflow definition, instance, and execution
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	execution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(execution).Error; err != nil {
		t.Fatalf("Failed to create test workflow execution: %v", err)
	}

	// Create step definitions
	stepDef1 := createTestWorkflowStepDefinition(workflowDef.ID)
	stepDef2 := createTestWorkflowStepDefinition(workflowDef.ID)
	if err := db.Create(stepDef1).Error; err != nil {
		t.Fatalf("Failed to create step definition 1: %v", err)
	}
	if err := db.Create(stepDef2).Error; err != nil {
		t.Fatalf("Failed to create step definition 2: %v", err)
	}

	// Create step executions
	stepExecution1 := createTestStepExecution(execution.ID, stepDef1.ID)
	stepExecution1.Status = "completed"

	stepExecution2 := createTestStepExecution(execution.ID, stepDef2.ID)
	stepExecution2.Status = "in_progress"

	if err := db.Create(stepExecution1).Error; err != nil {
		t.Fatalf("Failed to create step execution 1: %v", err)
	}
	if err := db.Create(stepExecution2).Error; err != nil {
		t.Fatalf("Failed to create step execution 2: %v", err)
	}

	// Test getting progress
	completed, total, err := service.GetExecutionProgress(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Equal(t, 1, completed)

	// Test with execution that has no step executions
	emptyExecution := createTestWorkflowExecution(instance.ID)
	if err := db.Create(emptyExecution).Error; err != nil {
		t.Fatalf("Failed to create empty execution: %v", err)
	}

	completed, total, err = service.GetExecutionProgress(emptyExecution.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Equal(t, 0, completed)
}

// TestWorkflowExecutionService_Integration tests integration scenarios
func TestWorkflowExecutionService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowExecutionService(db)

	// Create a complete workflow setup
	workflowDef := createTestWorkflowDefinition()
	workflowDef.Name = "Integration Test Workflow"
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create step definitions
	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Step 1: Data Collection"
	step1.ResponsibleRole = "data_analyst"

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Step 2: Analysis"
	step2.ResponsibleRole = "analyst"

	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create step 1: %v", err)
	}
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create step 2: %v", err)
	}
	sysId := uuid.New()
	// Create workflow instance
	instance := createTestWorkflowInstance(workflowDef.ID)
	instance.Name = "Integration Test Instance"
	instance.SystemSecurityPlanID = &sysId
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Create workflow execution
	execution := createTestWorkflowExecution(instance.ID)
	execution.TriggeredBy = "manual"
	execution.TriggeredByID = "test_user"
	if err := service.Create(execution); err != nil {
		t.Fatalf("Failed to create execution: %v", err)
	}

	// Create step executions
	stepExec1 := createTestStepExecution(execution.ID, step1.ID)
	stepExec1.Status = "completed"
	stepExec1.AssignedToType = "user"
	stepExec1.AssignedToID = "user123"

	stepExec2 := createTestStepExecution(execution.ID, step2.ID)
	stepExec2.Status = "in_progress"
	stepExec2.AssignedToType = "user"
	stepExec2.AssignedToID = "user456"

	if err := db.Create(stepExec1).Error; err != nil {
		t.Fatalf("Failed to create step execution 1: %v", err)
	}
	if err := db.Create(stepExec2).Error; err != nil {
		t.Fatalf("Failed to create step execution 2: %v", err)
	}

	// Retrieve execution with all relationships
	retrieved, err := service.GetByID(execution.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "manual", retrieved.TriggeredBy)
	assert.Equal(t, "test_user", retrieved.TriggeredByID)
	assert.NotNil(t, retrieved.WorkflowInstance)
	assert.NotNil(t, retrieved.WorkflowInstance.WorkflowDefinition)
	assert.Len(t, retrieved.StepExecutions, 2)

	// Verify step executions
	stepStatuses := make(map[string]bool)
	for _, stepExec := range retrieved.StepExecutions {
		stepStatuses[stepExec.Status] = true
	}
	assert.True(t, stepStatuses["completed"])
	assert.True(t, stepStatuses["in_progress"])

	// Test execution lifecycle
	err = service.Start(execution.ID)
	require.NoError(t, err)

	// Verify progress
	completedSteps, totalSteps, err := service.GetExecutionProgress(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, totalSteps)
	assert.Equal(t, 1, completedSteps)

	// Complete the execution
	err = service.Complete(execution.ID)
	require.NoError(t, err)

	// Verify completion
	completedExecution, err := service.GetByID(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", completedExecution.Status)
	assert.NotNil(t, completedExecution.CompletedAt)

	// Test filtering executions
	filters := map[string]interface{}{
		"status":               "completed",
		"workflow_instance_id": instance.ID,
	}
	filtered, total, err := service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "completed", filtered[0].Status)

	// Test getting executions by instance
	instanceExecutions, err := service.GetByWorkflowInstanceID(instance.ID)
	require.NoError(t, err)
	assert.Len(t, instanceExecutions, 1)
	assert.Equal(t, execution.ID, instanceExecutions[0].ID)
}
