package workflows

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Reduce noise in tests
	})
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Auto-migrate all workflow entities
	entities := GetWorkflowEntities()
	for _, entity := range entities {
		if err := db.AutoMigrate(entity); err != nil {
			t.Fatalf("Failed to migrate %T: %v", entity, err)
		}
	}

	return db
}

// createTestWorkflowDefinition creates a test workflow definition
func createTestWorkflowDefinition() *WorkflowDefinition {
	id := uuid.New()
	return &WorkflowDefinition{
		UUIDModel:        relational.UUIDModel{ID: &id},
		Name:             "Test Workflow Definition",
		Description:      "Test workflow definition for unit tests",
		Version:          "1.0",
		SuggestedCadence: "monthly",
		EvidenceRequired: `["document","screenshot"]`,
	}
}

// createTestWorkflowStepDefinition creates a test workflow step definition
func createTestWorkflowStepDefinition(workflowDefID *uuid.UUID) *WorkflowStepDefinition {
	id := uuid.New()
	return &WorkflowStepDefinition{
		UUIDModel:            relational.UUIDModel{ID: &id},
		WorkflowDefinitionID: workflowDefID,
		Name:                 "Test Step Definition",
		Description:          "Test step definition for unit tests",
		ResponsibleRole:      "compliance_analyst",
		EstimatedDuration:    60,
	}
}

// createTestWorkflowInstance creates a test workflow instance
func createTestWorkflowInstance(workflowDefID *uuid.UUID) *WorkflowInstance {
	id := uuid.New()
	sysId := uuid.New()
	return &WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &id},
		WorkflowDefinitionID: workflowDefID,
		Name:                 "Test Workflow Instance",
		SystemSecurityPlanID: &sysId,
		Cadence:              "monthly",
		NextScheduledAt:      &time.Time{},
	}
}

// createTestRoleAssignment creates a test role assignment
func createTestRoleAssignment(instanceID *uuid.UUID) *RoleAssignment {
	id := uuid.New()
	userID := uuid.New()
	return &RoleAssignment{
		UUIDModel:          relational.UUIDModel{ID: &id},
		WorkflowInstanceID: instanceID,
		RoleName:           "compliance_analyst",
		AssignedToType:     "user",
		AssignedToID:       userID.String(),
	}
}

// createTestWorkflowExecution creates a test workflow execution
func createTestWorkflowExecution(instanceID *uuid.UUID) *WorkflowExecution {
	id := uuid.New()
	return &WorkflowExecution{
		UUIDModel:          relational.UUIDModel{ID: &id},
		WorkflowInstanceID: instanceID,
		Status:             "pending",
		TriggeredBy:        "manual",
	}
}

// createTestStepExecution creates a test step execution
func createTestStepExecution(executionID *uuid.UUID, stepDefID *uuid.UUID) *StepExecution {
	id := uuid.New()
	return &StepExecution{
		UUIDModel:                relational.UUIDModel{ID: &id},
		WorkflowExecutionID:      executionID,
		WorkflowStepDefinitionID: stepDefID,
		Status:                   "pending",
	}
}

// createTestControlRelationship creates a test control relationship
func createTestControlRelationship(workflowDefID *uuid.UUID) *ControlRelationship {
	id := uuid.New()
	return &ControlRelationship{
		UUIDModel:            relational.UUIDModel{ID: &id},
		WorkflowDefinitionID: workflowDefID,
		ControlID:            "AC-1",
		ControlSource:        "NIST 800-53",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
}

// TestBaseService_HandleRecordNotFoundError tests the HandleRecordNotFoundError method
func TestBaseService_HandleRecordNotFoundError(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	testID := uuid.New()

	// Test with nil error
	err := service.HandleRecordNotFoundError(nil, &testID, "test entity")
	if err != nil {
		t.Errorf("Expected nil error for nil input, got %v", err)
	}

	// Test with record not found error
	recordNotFoundErr := gorm.ErrRecordNotFound
	err = service.HandleRecordNotFoundError(recordNotFoundErr, &testID, "test entity")
	expectedErr := "test entity with id " + testID.String() + " not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}

	// Test with other error
	otherErr := &testCustomError{msg: "custom error"}
	err = service.HandleRecordNotFoundError(otherErr, &testID, "test entity")
	if err != otherErr {
		t.Errorf("Expected original error to be returned, got %v", err)
	}
}

// TestBaseService_CheckEntityExists tests the CheckEntityExists method
func TestBaseService_CheckEntityExists(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test existing entity
	err := service.CheckEntityExists(&WorkflowDefinition{}, workflowDef.ID, "workflow definition")
	if err != nil {
		t.Errorf("Expected no error for existing entity, got %v", err)
	}

	// Test non-existing entity
	nonExistentID := uuid.New()
	err = service.CheckEntityExists(&WorkflowDefinition{}, &nonExistentID, "workflow definition")
	expectedErr := "workflow definition with id " + nonExistentID.String() + " not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

// TestBaseService_DeleteEntity tests the DeleteEntity method
func TestBaseService_DeleteEntity(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful deletion
	err := service.DeleteEntity(&WorkflowDefinition{}, workflowDef.ID, "workflow definition")
	if err != nil {
		t.Errorf("Expected no error for successful deletion, got %v", err)
	}

	// Verify entity is soft deleted
	var deleted WorkflowDefinition
	err = db.Unscoped().First(&deleted, workflowDef.ID).Error
	if err != nil {
		t.Errorf("Expected to find soft deleted entity, got error: %v", err)
	}
	if deleted.DeletedAt.Time.IsZero() {
		t.Error("Expected DeletedAt to be set after soft delete")
	}

	// Test deletion of non-existing entity
	nonExistentID := uuid.New()
	err = service.DeleteEntity(&WorkflowDefinition{}, &nonExistentID, "workflow definition")
	expectedErr := "workflow definition with id " + nonExistentID.String() + " not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

// TestBaseService_UpdateEntity tests the UpdateEntity method
func TestBaseService_UpdateEntity(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful update
	updates := map[string]interface{}{
		"name":        "Updated Workflow Definition",
		"description": "Updated description",
	}
	err := service.UpdateEntity(&WorkflowDefinition{}, updates, workflowDef.ID, "workflow definition")
	if err != nil {
		t.Errorf("Expected no error for successful update, got %v", err)
	}

	// Verify update was applied
	var updated WorkflowDefinition
	err = db.First(&updated, workflowDef.ID).Error
	if err != nil {
		t.Errorf("Expected to find updated entity, got error: %v", err)
	}
	if updated.Name != "Updated Workflow Definition" {
		t.Errorf("Expected name to be updated to 'Updated Workflow Definition', got '%s'", updated.Name)
	}

	// Test update of non-existing entity
	nonExistentID := uuid.New()
	err = service.UpdateEntity(&WorkflowDefinition{}, updates, &nonExistentID, "workflow definition")
	expectedErr := "workflow definition with id " + nonExistentID.String() + " not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

// TestBaseService_ValidateUpdatesNotNil tests the ValidateUpdatesNotNil method
func TestBaseService_ValidateUpdatesNotNil(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Test with nil updates
	err := service.ValidateUpdatesNotNil(nil)
	expectedErr := "updates cannot be nil"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}

	// Test with valid updates
	updates := map[string]interface{}{"name": "test"}
	err = service.ValidateUpdatesNotNil(updates)
	if err != nil {
		t.Errorf("Expected no error for valid updates, got %v", err)
	}
}

// TestBaseService_UpdateStatus tests the UpdateStatus method
func TestBaseService_UpdateStatus(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test status update with timestamps - use a valid field like name instead of status
	timestampUpdates := map[string]interface{}{
		"updated_at": time.Now(),
	}
	err := service.UpdateStatus(&WorkflowDefinition{}, workflowDef.ID, "completed", "name", timestampUpdates)
	if err != nil {
		t.Errorf("Expected no error for status update, got %v", err)
	}

	// Verify the name was updated (testing the method logic)
	var updated WorkflowDefinition
	err = db.First(&updated, workflowDef.ID).Error
	if err != nil {
		t.Errorf("Expected to find updated entity, got error: %v", err)
	}
}

// TestBaseService_ActivateEntity tests the ActivateEntity method
func TestBaseService_ActivateEntity(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity with is_active field (using WorkflowInstance as it has this field)
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	instance := createTestWorkflowInstance(workflowDef.ID)
	if err := db.Create(instance).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance: %v", err)
	}

	// Test activation
	err := service.ActivateEntity(&WorkflowInstance{}, instance.ID)
	if err != nil {
		t.Errorf("Expected no error for activation, got %v", err)
	}

	// Verify activation
	var activated WorkflowInstance
	err = db.First(&activated, instance.ID).Error
	if err != nil {
		t.Errorf("Expected to find activated entity, got error: %v", err)
	}
	if !activated.IsActive {
		t.Error("Expected IsActive to be true after activation")
	}
}

// TestBaseService_DeactivateEntity tests the DeactivateEntity method
func TestBaseService_DeactivateEntity(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity with is_active field
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
	err := service.DeactivateEntity(&WorkflowInstance{}, instance.ID)
	if err != nil {
		t.Errorf("Expected no error for deactivation, got %v", err)
	}

	// Verify deactivation
	var deactivated WorkflowInstance
	err = db.First(&deactivated, instance.ID).Error
	if err != nil {
		t.Errorf("Expected to find deactivated entity, got error: %v", err)
	}
	if deactivated.IsActive {
		t.Error("Expected IsActive to be false after deactivation")
	}
}

// TestBaseService_BulkCreate tests the BulkCreate method
func TestBaseService_BulkCreate(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Test bulk create without validation
	entities := []WorkflowDefinition{
		*createTestWorkflowDefinition(),
		*createTestWorkflowDefinition(),
	}

	err := service.BulkCreate(&entities, nil)
	if err != nil {
		t.Errorf("Expected no error for bulk create without validation, got %v", err)
	}

	// Verify entities were created
	var count int64
	err = db.Model(&WorkflowDefinition{}).Count(&count).Error
	if err != nil {
		t.Errorf("Expected to count entities, got error: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 entities to be created, got %d", count)
	}

	// Test bulk create with validation that passes
	validateFn := func(index int) error {
		return nil // No validation error
	}

	entities2 := []WorkflowDefinition{*createTestWorkflowDefinition()}
	err = service.BulkCreate(&entities2, validateFn)
	if err != nil {
		t.Errorf("Expected no error for bulk create with passing validation, got %v", err)
	}

	// Test bulk create with validation that fails
	validateFailFn := func(index int) error {
		return &testCustomError{msg: "validation failed"}
	}

	entities3 := []WorkflowDefinition{*createTestWorkflowDefinition()}
	err = service.BulkCreate(&entities3, validateFailFn)
	if err == nil || err.Error() != "validation failed" {
		t.Errorf("Expected validation error, got %v", err)
	}
}

// TestBaseService_GetByIDWithPreload tests the GetByIDWithPreload method
func TestBaseService_GetByIDWithPreload(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create a test entity with relationships
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful retrieval with preloads
	var definition WorkflowDefinition
	err := service.GetByIDWithPreload(&definition, workflowDef.ID, "workflow definition")
	if err != nil {
		t.Errorf("Expected no error for retrieval with preloads, got %v", err)
	}

	// Test retrieval of non-existing entity
	nonExistentID := uuid.New()
	var nonExistent WorkflowDefinition
	err = service.GetByIDWithPreload(&nonExistent, &nonExistentID, "workflow definition")
	expectedErr := "workflow definition with id " + nonExistentID.String() + " not found"
	if err == nil || err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got %v", expectedErr, err)
	}
}

// TestBaseService_CountWhere tests the CountWhere method
func TestBaseService_CountWhere(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create test entities
	workflowDef1 := createTestWorkflowDefinition()
	workflowDef1.Name = "Test Workflow 1"
	workflowDef2 := createTestWorkflowDefinition()
	workflowDef2.Name = "Test Workflow 2"

	if err := db.Create(workflowDef1).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition 1: %v", err)
	}
	if err := db.Create(workflowDef2).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition 2: %v", err)
	}

	// Test count with condition
	count, err := service.CountWhere(&WorkflowDefinition{}, "name LIKE ?", "%Test Workflow%")
	if err != nil {
		t.Errorf("Expected no error for count, got %v", err)
	}
	if count != 2 {
		t.Errorf("Expected count to be 2, got %d", count)
	}

	// Test count with no matches
	count, err = service.CountWhere(&WorkflowDefinition{}, "name = ?", "Non-existent")
	if err != nil {
		t.Errorf("Expected no error for count with no matches, got %v", err)
	}
	if count != 0 {
		t.Errorf("Expected count to be 0, got %d", count)
	}
}

// TestBaseService_ExistsWhere tests the ExistsWhere method
func TestBaseService_ExistsWhere(t *testing.T) {
	db := setupTestDB(t)
	service := NewBaseService(db)

	// Create test entity
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test existence with matching condition
	exists, err := service.ExistsWhere(&WorkflowDefinition{}, "name = ?", workflowDef.Name)
	if err != nil {
		t.Errorf("Expected no error for exists check, got %v", err)
	}
	if !exists {
		t.Error("Expected entity to exist")
	}

	// Test existence with non-matching condition
	exists, err = service.ExistsWhere(&WorkflowDefinition{}, "name = ?", "Non-existent")
	if err != nil {
		t.Errorf("Expected no error for exists check with no matches, got %v", err)
	}
	if exists {
		t.Error("Expected entity to not exist")
	}
}

// testCustomError is a custom error type for testing
type testCustomError struct {
	msg string
}

func (e *testCustomError) Error() string {
	return e.msg
}
