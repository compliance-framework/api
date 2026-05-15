package workflows

import (
	"context"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestWorkflowInstanceService_Create tests the Create method
func TestWorkflowInstanceService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition first
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful creation
	instance := createTestWorkflowInstance(workflowDef.ID)
	err := service.Create(instance)
	require.NoError(t, err)
	require.NotNil(t, instance.ID)

	// Verify in database
	var found WorkflowInstance
	err = db.First(&found, instance.ID).Error
	require.NoError(t, err)
	assert.Equal(t, instance.Name, found.Name)

	// Test with nil instance
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance cannot be nil")

	// Test with empty name
	invalidInstance := createTestWorkflowInstance(workflowDef.ID)
	invalidInstance.Name = ""
	err = service.Create(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "instance name is required")

	// Test with empty system name
	invalidInstance = createTestWorkflowInstance(workflowDef.ID)
	invalidInstance.SystemSecurityPlanID = nil
	err = service.Create(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "system security plan ID is required")

	// Test with nil workflow definition ID
	invalidInstance = createTestWorkflowInstance(nil)
	err = service.Create(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition ID is required")

	// Test automatic schedule calculation
	instanceWithCadence := createTestWorkflowInstance(workflowDef.ID)
	instanceWithCadence.Cadence = "daily"
	instanceWithCadence.NextScheduledAt = nil // Should be calculated automatically
	err = service.Create(instanceWithCadence)
	require.NoError(t, err)
	require.NotNil(t, instanceWithCadence.NextScheduledAt)
}

// TestWorkflowInstanceService_GetByID tests the GetByID method
func TestWorkflowInstanceService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test successful retrieval
	retrieved, err := service.GetByID(instance.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, instance.Name, retrieved.Name)
	assert.NotNil(t, retrieved.WorkflowDefinition)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "workflow instance with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowInstanceService_GetAll tests the GetAll method
func TestWorkflowInstanceService_GetAll(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create multiple instances
	instances := []*WorkflowInstance{
		createTestWorkflowInstance(workflowDef.ID),
		createTestWorkflowInstance(workflowDef.ID),
		createTestWorkflowInstance(workflowDef.ID),
	}
	sysId := uuid.New()

	for i, instance := range instances {
		instance.Name = "Instance " + string(rune('A'+i))
		instance.SystemSecurityPlanID = &sysId
		if err := db.Create(instance).Error; err != nil {
			t.Fatalf("Failed to create test workflow instance %d: %v", i, err)
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

	// Test with filters
	filters := map[string]interface{}{
		"system_security_plan_id": &sysId,
		"is_active":               true,
	}
	retrieved, total, err = service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 3)
	assert.Equal(t, sysId, *retrieved[0].SystemSecurityPlanID)

	// Test with workflow definition filter
	filters = map[string]interface{}{
		"workflow_definition_id": workflowDef.ID,
	}
	retrieved, total, err = service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 3)
}

// TestWorkflowInstanceService_GetByWorkflowDefinitionID tests the GetByWorkflowDefinitionID method
func TestWorkflowInstanceService_GetByWorkflowDefinitionID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create multiple instances for the workflow
	instances := []*WorkflowInstance{
		createTestWorkflowInstance(workflowDef.ID),
		createTestWorkflowInstance(workflowDef.ID),
		createTestWorkflowInstance(workflowDef.ID),
	}

	for i, instance := range instances {
		instance.Name = "Instance " + string(rune('A'+i))
		if err := db.Create(instance).Error; err != nil {
			t.Fatalf("Failed to create test workflow instance %d: %v", i, err)
		}
	}

	// Test retrieval
	retrieved, err := service.GetByWorkflowDefinitionID(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, retrieved, 3)

	// Test with non-existent workflow definition ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByWorkflowDefinitionID(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, retrieved, 0)
}

// TestWorkflowInstanceService_Update tests the Update method
func TestWorkflowInstanceService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}
	sysId := uuid.New()
	// Test successful update
	updates := &WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: instance.ID},
		WorkflowDefinitionID: instance.WorkflowDefinitionID,
		Name:                 "Updated Instance",
		Description:          "Updated description",
		SystemSecurityPlanID: &sysId,
		Cadence:              "weekly",
	}
	err := service.Update(instance.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated WorkflowInstance
	err = db.First(&updated, instance.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "Updated Instance", updated.Name)
	assert.Equal(t, sysId, *updated.SystemSecurityPlanID)
	assert.Equal(t, "weekly", updated.Cadence)

	// Test with nil updates
	err = service.Update(instance.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	updatesWithNonExistentID := &WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &nonExistentID},
		WorkflowDefinitionID: workflowDef.ID,
		Name:                 "Updated Instance",
		SystemSecurityPlanID: &sysId,
	}
	err = service.Update(&nonExistentID, updatesWithNonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowInstanceService_Delete tests the Delete method
func TestWorkflowInstanceService_Delete(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test successful deletion
	err := service.Delete(instance.ID)
	require.NoError(t, err)

	// Verify soft deletion
	var deleted WorkflowInstance
	err = db.Unscoped().First(&deleted, instance.ID).Error
	require.NoError(t, err)
	assert.NotNil(t, deleted.DeletedAt)

	// Verify it's not found with normal query
	var notFound WorkflowInstance
	err = db.First(&notFound, instance.ID).Error
	assert.Error(t, err)
	assert.Equal(t, gorm.ErrRecordNotFound, err)

	// Test deletion of non-existent instance
	nonExistentID := uuid.New()
	err = service.Delete(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowInstanceService_Activate tests the Activate method
func TestWorkflowInstanceService_Activate(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	instance.IsActive = false
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test activation
	err := service.Activate(instance.ID)
	require.NoError(t, err)

	// Verify activation
	var activated WorkflowInstance
	err = db.First(&activated, instance.ID).Error
	require.NoError(t, err)
	assert.True(t, activated.IsActive)
}

// TestWorkflowInstanceService_Deactivate tests the Deactivate method
func TestWorkflowInstanceService_Deactivate(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	instance.IsActive = true
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test deactivation
	err := service.Deactivate(instance.ID)
	require.NoError(t, err)

	// Verify deactivation
	var deactivated WorkflowInstance
	err = db.First(&deactivated, instance.ID).Error
	require.NoError(t, err)
	assert.False(t, deactivated.IsActive)
}

// TestWorkflowInstanceService_UpdateSchedule tests the UpdateSchedule method
func TestWorkflowInstanceService_UpdateSchedule(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test schedule update
	newSchedule := time.Now().Add(24 * time.Hour)
	err := service.UpdateSchedule(context.Background(), instance.ID, newSchedule)
	require.NoError(t, err)

	// Verify update
	var updated WorkflowInstance
	err = db.First(&updated, instance.ID).Error
	require.NoError(t, err)
	assert.WithinDuration(t, newSchedule, *updated.NextScheduledAt, time.Second)
}

// TestWorkflowInstanceService_UpdateLastExecuted tests the UpdateLastExecuted method
func TestWorkflowInstanceService_UpdateLastExecuted(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test last executed update
	lastExecuted := time.Now()
	err := service.UpdateLastExecuted(context.Background(), instance.ID, lastExecuted)
	require.NoError(t, err)

	// Verify update
	var updated WorkflowInstance
	err = db.First(&updated, instance.ID).Error
	require.NoError(t, err)
	assert.WithinDuration(t, lastExecuted, *updated.LastExecutedAt, time.Second)
}

// TestWorkflowInstanceService_GetDueInstances tests the GetDueInstances method
func TestWorkflowInstanceService_GetDueInstances(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create instances with different schedules
	pastTime1 := time.Now().Add(-1 * time.Hour)
	pastTime2 := time.Now().Add(-2 * time.Hour) // Different past time
	futureTime := time.Now().Add(1 * time.Hour)

	dueInstance := createTestWorkflowInstance(workflowDef.ID)
	dueInstance.IsActive = true
	dueInstance.NextScheduledAt = &pastTime1

	notDueInstance := createTestWorkflowInstance(workflowDef.ID)
	notDueInstance.IsActive = true
	notDueInstance.NextScheduledAt = &futureTime

	inactiveInstance := createTestWorkflowInstance(workflowDef.ID)
	inactiveInstance.NextScheduledAt = &pastTime2 // Use different time to avoid conflicts

	// Create the inactive instance first, then update it to be inactive
	if err := db.Create(inactiveInstance).Error; err != nil {
		t.Fatalf("Failed to create inactive instance: %v", err)
	}
	// Now update it to be inactive
	if err := db.Model(inactiveInstance).Update("is_active", false).Error; err != nil {
		t.Fatalf("Failed to set instance to inactive: %v", err)
	}

	// Verify the inactive instance is actually inactive
	var checkInactive WorkflowInstance
	if err := db.First(&checkInactive, inactiveInstance.ID).Error; err != nil {
		t.Fatalf("Failed to retrieve inactive instance: %v", err)
	}
	assert.False(t, checkInactive.IsActive, "Inactive instance should be false after update")

	// Create instances with a small delay to ensure different creation times
	if err := db.Create(dueInstance).Error; err != nil {
		t.Fatalf("Failed to create due instance: %v", err)
	}
	time.Sleep(1 * time.Millisecond) // Small delay
	if err := db.Create(notDueInstance).Error; err != nil {
		t.Fatalf("Failed to create not due instance: %v", err)
	}
	// Note: inactiveInstance was already created above

	// Test getting due instances
	dueInstances, err := service.GetDueInstances(context.Background())
	require.NoError(t, err)

	// Debug: Print what we actually got
	t.Logf("Found %d due instances:", len(dueInstances))
	for i, instance := range dueInstances {
		t.Logf("  Instance %d: ID=%s, IsActive=%t, NextScheduledAt=%v",
			i, instance.ID.String(), instance.IsActive, instance.NextScheduledAt)
	}

	// The query should only return active instances with past due times
	// We expect only the dueInstance to be returned
	assert.Len(t, dueInstances, 1, "Expected exactly 1 due instance")
	assert.Equal(t, dueInstance.ID, dueInstances[0].ID, "Expected the due instance to be returned")
}

// TestWorkflowInstanceService_GetBySystemId tests the GetBySystemId method
func TestWorkflowInstanceService_GetBySystemId(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}
	sysId1 := uuid.New()
	sysId2 := uuid.New()
	// Create instances for different systems
	instance1 := createTestWorkflowInstance(workflowDef.ID)
	instance1.SystemSecurityPlanID = &sysId1

	instance2 := createTestWorkflowInstance(workflowDef.ID)
	instance2.SystemSecurityPlanID = &sysId2

	instance3 := createTestWorkflowInstance(workflowDef.ID)
	instance3.SystemSecurityPlanID = &sysId1

	if err := db.Create(instance1).Error; err != nil {
		t.Fatalf("Failed to create instance 1: %v", err)
	}
	if err := db.Create(instance2).Error; err != nil {
		t.Fatalf("Failed to create instance 2: %v", err)
	}
	if err := db.Create(instance3).Error; err != nil {
		t.Fatalf("Failed to create instance 3: %v", err)
	}

	// Test getting instances by system security plan ID
	instances, err := service.GetBySystemId(&sysId1)
	require.NoError(t, err)
	assert.Len(t, instances, 2)

	// Verify system security plan IDs
	for _, instance := range instances {
		assert.Equal(t, sysId1, *instance.SystemSecurityPlanID)
	}

	// Test with non-existent system security plan ID
	unexisting := uuid.New()
	instances, err = service.GetBySystemId(&unexisting)
	require.NoError(t, err)
	assert.Len(t, instances, 0)
}

// TestWorkflowInstanceService_ValidateInstance tests the ValidateInstance method
func TestWorkflowInstanceService_ValidateInstance(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Test valid instance
	testUUID := uuid.New()
	validInstance := createTestWorkflowInstance(&testUUID)
	err := service.ValidateInstance(validInstance)
	assert.NoError(t, err)

	// Test nil instance
	err = service.ValidateInstance(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance cannot be nil")

	// Test empty name
	testUUID2 := uuid.New()
	invalidInstance := createTestWorkflowInstance(&testUUID2)
	invalidInstance.Name = ""
	err = service.ValidateInstance(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "instance name is required")

	// Test name too long
	testUUID3 := uuid.New()
	invalidInstance = createTestWorkflowInstance(&testUUID3)
	invalidInstance.Name = string(make([]byte, MaxNameLength+1))
	err = service.ValidateInstance(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "instance name cannot exceed")

	// Test empty system name
	testUUID4 := uuid.New()
	invalidInstance = createTestWorkflowInstance(&testUUID4)
	invalidInstance.SystemSecurityPlanID = nil
	err = service.ValidateInstance(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "system security plan ID is required")

	// Test nil workflow definition ID
	invalidInstance = createTestWorkflowInstance(nil)
	err = service.ValidateInstance(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition ID is required")

	// Test invalid cadence
	testUUID6 := uuid.New()
	invalidInstance = createTestWorkflowInstance(&testUUID6)
	invalidInstance.Cadence = "invalid"
	err = service.ValidateInstance(invalidInstance)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cadence")
}

func TestWorkflowInstanceService_ValidateInstanceGracePeriodHierarchy(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	missingDefinitionID := uuid.New()
	missingDefinitionGrace := 1
	missingDefinitionInstance := createTestWorkflowInstance(&missingDefinitionID)
	missingDefinitionInstance.GracePeriodDays = &missingDefinitionGrace

	err := service.ValidateInstance(missingDefinitionInstance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition not found")

	definitionGrace := 5
	definition := createTestWorkflowDefinition()
	definition.GracePeriodDays = &definitionGrace
	require.NoError(t, db.Create(definition).Error)

	instanceGrace := 6
	instance := createTestWorkflowInstance(definition.ID)
	instance.GracePeriodDays = &instanceGrace

	err = service.ValidateInstance(instance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance grace period days must be less than or equal")

	instanceGrace = 4
	instance.GracePeriodDays = &instanceGrace
	stepGrace := 5
	step := createTestWorkflowStepDefinition(definition.ID)
	step.GracePeriodDays = &stepGrace
	require.NoError(t, db.Create(step).Error)

	err = service.ValidateInstance(instance)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance grace period days must be greater than or equal")
}

// TestWorkflowInstanceService_calculateNextSchedule tests the calculateNextSchedule method
func TestWorkflowInstanceService_calculateNextSchedule(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	baseTime := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)

	// Test daily cadence
	next := service.calculateNextSchedule(baseTime, "daily")
	expected := baseTime.AddDate(0, 0, 1)
	assert.Equal(t, expected, next)

	// Test weekly cadence
	next = service.calculateNextSchedule(baseTime, "weekly")
	expected = baseTime.AddDate(0, 0, 7)
	assert.Equal(t, expected, next)

	// Test monthly cadence
	next = service.calculateNextSchedule(baseTime, "monthly")
	expected = baseTime.AddDate(0, 1, 0)
	assert.Equal(t, expected, next)

	// Test quarterly cadence
	next = service.calculateNextSchedule(baseTime, "quarterly")
	expected = baseTime.AddDate(0, 3, 0)
	assert.Equal(t, expected, next)

	// Test annually cadence
	next = service.calculateNextSchedule(baseTime, "annually")
	expected = baseTime.AddDate(1, 0, 0)
	assert.Equal(t, expected, next)

	// Test invalid cadence (should default to monthly)
	next = service.calculateNextSchedule(baseTime, "invalid")
	expected = baseTime.AddDate(0, 1, 0)
	assert.Equal(t, expected, next)

	// Test valid cron expression (6-field format: second minute hour day-of-month month day-of-week)
	// "0 0 9 * * *" means daily at 9:00:00 AM
	next = service.calculateNextSchedule(baseTime, "cron:0 0 9 * * *")
	// baseTime is 2024-01-15 10:00:00, so next 9 AM is 2024-01-16 09:00:00
	expected = time.Date(2024, 1, 16, 9, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)

	// Test cron expression that matches later same day
	morningTime := time.Date(2024, 1, 15, 8, 0, 0, 0, time.UTC)
	next = service.calculateNextSchedule(morningTime, "cron:0 0 9 * * *")
	// 8 AM, so next 9 AM is same day
	expected = time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)

	// Test weekly cron (every Monday at 9 AM)
	// "0 0 9 * * 1" = second 0, minute 0, hour 9, any day-of-month, any month, Monday
	next = service.calculateNextSchedule(baseTime, "cron:0 0 9 * * 1")
	// 2024-01-15 is Monday, 10 AM, so next Monday 9 AM is 2024-01-22
	expected = time.Date(2024, 1, 22, 9, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

// TestWorkflowInstanceService_CronValidation tests cron expression validation
func TestWorkflowInstanceService_CronValidation(t *testing.T) {
	// Test valid cron expressions
	validCrons := []string{
		"cron:0 0 9 * * *",   // Daily at 9 AM
		"cron:0 30 14 * * *", // Daily at 2:30 PM
		"cron:0 0 0 1 * *",   // First of every month at midnight
		"cron:0 0 9 * * 1",   // Every Monday at 9 AM
		"cron:0 0 9 * * 1-5", // Weekdays at 9 AM
		"cron:0 0 */2 * * *", // Every 2 hours
	}

	for _, cronStr := range validCrons {
		cadence := CadenceType(cronStr)
		assert.True(t, cadence.IsValid(), "Expected %s to be valid", cronStr)
		assert.Nil(t, cadence.ValidateCronExpression(), "Expected %s to have no validation error", cronStr)
	}

	// Test invalid cron expressions
	invalidCrons := []string{
		"cron:invalid",      // Not a valid cron format
		"cron:* * *",        // Too few fields (3 instead of 6)
		"cron:0 0 25 * * *", // Invalid hour (25)
		"cron:0 60 9 * * *", // Invalid minute (60)
		"cron:0 0 9 32 * *", // Invalid day-of-month (32)
	}

	for _, cronStr := range invalidCrons {
		cadence := CadenceType(cronStr)
		assert.False(t, cadence.IsValid(), "Expected %s to be invalid", cronStr)
		assert.NotNil(t, cadence.ValidateCronExpression(), "Expected %s to have validation error", cronStr)
	}
}

// TestWorkflowInstanceService_CronHelperMethods tests IsCron and CronExpression methods
func TestWorkflowInstanceService_CronHelperMethods(t *testing.T) {
	// Test IsCron
	assert.True(t, CadenceType("cron:0 0 9 * * *").IsCron())
	assert.True(t, CadenceType("cron:anything").IsCron())
	assert.False(t, CadenceType("daily").IsCron())
	assert.False(t, CadenceType("monthly").IsCron())
	assert.False(t, CadenceType("cron:").IsCron()) // Empty expression after prefix
	assert.False(t, CadenceType("cron").IsCron())  // No colon

	// Test CronExpression extraction
	assert.Equal(t, "0 0 9 * * *", CadenceType("cron:0 0 9 * * *").CronExpression())
	assert.Equal(t, "anything", CadenceType("cron:anything").CronExpression())
	assert.Equal(t, "", CadenceType("daily").CronExpression())
	assert.Equal(t, "", CadenceType("monthly").CronExpression())
}

// TestWorkflowInstanceService_Integration tests integration scenarios
func TestWorkflowInstanceService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowInstanceService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	workflowDef.Name = "Complex Workflow"
	workflowDef.SuggestedCadence = "monthly"
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create instances with role assignments
	instance := createTestWorkflowInstance(workflowDef.ID)
	instance.Name = "Production Instance"
	instance.Cadence = "monthly"
	instance.IsActive = true

	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create instance: %v", err)
	}

	// Create role assignments
	role1 := createTestRoleAssignment(instance.ID)
	role1.RoleName = "security_analyst"

	role2 := createTestRoleAssignment(instance.ID)
	role2.RoleName = "compliance_officer"

	if err := db.Create(role1).Error; err != nil {
		t.Fatalf("Failed to create role assignment 1: %v", err)
	}
	if err := db.Create(role2).Error; err != nil {
		t.Fatalf("Failed to create role assignment 2: %v", err)
	}

	// Retrieve instance with all relationships
	retrieved, err := service.GetByID(instance.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "Production Instance", retrieved.Name)
	assert.NotNil(t, retrieved.WorkflowDefinition)
	assert.Len(t, retrieved.RoleAssignments, 2)

	// Verify role assignments
	roleNames := make(map[string]bool)
	for _, role := range retrieved.RoleAssignments {
		roleNames[role.RoleName] = true
	}
	assert.True(t, roleNames["security_analyst"])
	assert.True(t, roleNames["compliance_officer"])

	// Test filtering instances
	filters := map[string]interface{}{
		"system_name": "Production System",
		"is_active":   true,
	}
	filtered, total, err := service.GetAll(10, 0, filters)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, filtered, 1)
	assert.Equal(t, "Production Instance", filtered[0].Name)

	// Test schedule management
	newSchedule := time.Now().Add(30 * 24 * time.Hour) // 30 days from now
	err = service.UpdateSchedule(context.Background(), instance.ID, newSchedule)
	require.NoError(t, err)

	// Verify schedule update
	updated, err := service.GetByID(instance.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, newSchedule, *updated.NextScheduledAt, time.Second)

	// Test activation/deactivation
	err = service.Deactivate(instance.ID)
	require.NoError(t, err)

	// Verify deactivation
	deactivated, err := service.GetByID(instance.ID)
	require.NoError(t, err)
	assert.False(t, deactivated.IsActive)

	// Reactivate
	err = service.Activate(instance.ID)
	require.NoError(t, err)

	// Verify reactivation
	reactivated, err := service.GetByID(instance.ID)
	require.NoError(t, err)
	assert.True(t, reactivated.IsActive)
}
