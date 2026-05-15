package workflows

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestWorkflowDefinitionService_Create tests the Create method
func TestWorkflowDefinitionService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Test successful creation
	definition := createTestWorkflowDefinition()
	err := service.Create(definition)
	require.NoError(t, err)
	require.NotNil(t, definition.ID)
	assert.Equal(t, "1.0", definition.Version) // Default version should be set

	// Verify in database
	var found WorkflowDefinition
	err = db.First(&found, definition.ID).Error
	require.NoError(t, err)
	assert.Equal(t, definition.Name, found.Name)

	// Test with nil definition
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition cannot be nil")

	// Test with empty name
	invalidDef := &WorkflowDefinition{}
	err = service.Create(invalidDef)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition name is required")
}

// TestWorkflowDefinitionService_GetByID tests the GetByID method
func TestWorkflowDefinitionService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create a test definition
	definition := createTestWorkflowDefinition()
	if err := db.Create(definition).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful retrieval
	retrieved, err := service.GetByID(definition.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, definition.Name, retrieved.Name)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "workflow definition with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowDefinitionService_GetAll tests the GetAll method
func TestWorkflowDefinitionService_GetAll(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create test definitions
	definitions := []*WorkflowDefinition{
		createTestWorkflowDefinition(),
		createTestWorkflowDefinition(),
		createTestWorkflowDefinition(),
	}

	for _, def := range definitions {
		def.Name = "Test Definition " + uuid.New().String()
		if err := db.Create(def).Error; err != nil {
			t.Fatalf("Failed to create test workflow definition: %v", err)
		}
	}

	// Test getting all with pagination
	retrieved, total, err := service.GetAll(10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 3)

	// Test pagination
	retrieved, total, err = service.GetAll(2, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	assert.Len(t, retrieved, 2)
}

// TestWorkflowDefinitionService_Update tests the Update method
func TestWorkflowDefinitionService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create a test definition
	definition := createTestWorkflowDefinition()
	if err := db.Create(definition).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful update
	updates := &WorkflowDefinition{
		UUIDModel:   relational.UUIDModel{ID: definition.ID}, // Set the ID properly
		Name:        "Updated Workflow Definition",
		Description: "Updated description",
		Version:     "2.0",
	}
	err := service.Update(definition.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated WorkflowDefinition
	err = db.First(&updated, definition.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "Updated Workflow Definition", updated.Name)
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, "2.0", updated.Version)

	// Test with nil updates
	err = service.Update(definition.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	updatesWithNonExistentID := &WorkflowDefinition{
		UUIDModel:   relational.UUIDModel{ID: &nonExistentID},
		Name:        "Updated Workflow Definition",
		Description: "Updated description",
		Version:     "2.0",
	}
	err = service.Update(&nonExistentID, updatesWithNonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowDefinitionService_Delete tests the Delete method
func TestWorkflowDefinitionService_Delete(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create a test definition
	definition := createTestWorkflowDefinition()
	if err := db.Create(definition).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful deletion
	err := service.Delete(definition.ID)
	require.NoError(t, err)

	// Verify soft deletion
	var deleted WorkflowDefinition
	err = db.Unscoped().First(&deleted, definition.ID).Error
	require.NoError(t, err)
	assert.NotNil(t, deleted.DeletedAt)

	// Verify it's not found with normal query
	var notFound WorkflowDefinition
	err = db.First(&notFound, definition.ID).Error
	assert.Error(t, err)
	assert.Equal(t, gorm.ErrRecordNotFound, err)

	// Test deletion of non-existent definition
	nonExistentID := uuid.New()
	err = service.Delete(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowDefinitionService_FindByName tests the FindByName method
func TestWorkflowDefinitionService_FindByName(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create test definitions with different names
	definitions := []*WorkflowDefinition{
		createTestWorkflowDefinition(),
		createTestWorkflowDefinition(),
		createTestWorkflowDefinition(),
	}

	definitions[0].Name = "Access Control Workflow"
	definitions[1].Name = "Data Access Control"
	definitions[2].Name = "Security Workflow"

	for _, def := range definitions {
		if err := db.Create(def).Error; err != nil {
			t.Fatalf("Failed to create test workflow definition: %v", err)
		}
	}

	// Test partial name search
	retrieved, err := service.FindByName("Control")
	require.NoError(t, err)
	assert.Len(t, retrieved, 2)

	// Test exact name search
	retrieved, err = service.FindByName("Access Control Workflow")
	require.NoError(t, err)
	assert.Len(t, retrieved, 1)
	assert.Equal(t, "Access Control Workflow", retrieved[0].Name)

	// Test no matches
	retrieved, err = service.FindByName("Non-existent")
	require.NoError(t, err)
	assert.Len(t, retrieved, 0)
}

// TestWorkflowDefinitionService_GetWithInstances tests the GetWithInstances method
func TestWorkflowDefinitionService_GetWithInstances(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create a test definition
	definition := createTestWorkflowDefinition()
	if err := db.Create(definition).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create instances for the definition
	instance1 := createTestWorkflowInstance(definition.ID)
	instance2 := createTestWorkflowInstance(definition.ID)

	if err := db.Create(instance1).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance 1: %v", err)
	}
	if err := db.Create(instance2).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance 2: %v", err)
	}

	// Test retrieval with instances
	retrieved, err := service.GetWithInstances(definition.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, definition.Name, retrieved.Name)
	assert.Len(t, retrieved.Instances, 2)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetWithInstances(&nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
}

// TestWorkflowDefinitionService_ValidateDefinition tests the ValidateDefinition method
func TestWorkflowDefinitionService_ValidateDefinition(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Test valid definition
	validDef := createTestWorkflowDefinition()
	err := service.ValidateDefinition(validDef)
	assert.NoError(t, err)

	// Test nil definition
	err = service.ValidateDefinition(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition cannot be nil")

	// Test empty name
	invalidDef := createTestWorkflowDefinition()
	invalidDef.Name = ""
	err = service.ValidateDefinition(invalidDef)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition name is required")

	// Test name too long
	invalidDef = createTestWorkflowDefinition()
	invalidDef.Name = string(make([]byte, MaxNameLength+1))
	err = service.ValidateDefinition(invalidDef)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition name cannot exceed")

	// Test invalid cadence
	invalidDef = createTestWorkflowDefinition()
	invalidDef.SuggestedCadence = "invalid"
	err = service.ValidateDefinition(invalidDef)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid cadence")
}

func TestWorkflowDefinitionService_ValidateDefinitionGracePeriodHierarchy(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	validDefinitionGrace := 10
	validDefinition := createTestWorkflowDefinition()
	validDefinition.GracePeriodDays = &validDefinitionGrace
	require.NoError(t, db.Create(validDefinition).Error)

	validInstanceGrace := 7
	validInstance := createTestWorkflowInstance(validDefinition.ID)
	validInstance.GracePeriodDays = &validInstanceGrace
	require.NoError(t, db.Create(validInstance).Error)

	validStepGrace := 6
	validStep := createTestWorkflowStepDefinition(validDefinition.ID)
	validStep.GracePeriodDays = &validStepGrace
	require.NoError(t, db.Create(validStep).Error)

	err := service.ValidateDefinition(validDefinition)
	require.NoError(t, err)

	definition := createTestWorkflowDefinition()
	grace := 5
	definition.GracePeriodDays = &grace
	require.NoError(t, db.Create(definition).Error)

	instanceGrace := 7
	instance := createTestWorkflowInstance(definition.ID)
	instance.GracePeriodDays = &instanceGrace
	require.NoError(t, db.Create(instance).Error)

	err = service.ValidateDefinition(definition)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition grace period days must be greater than or equal")

	instance.GracePeriodDays = nil
	require.NoError(t, db.Save(instance).Error)

	stepGrace := 6
	step := createTestWorkflowStepDefinition(definition.ID)
	step.GracePeriodDays = &stepGrace
	require.NoError(t, db.Create(step).Error)

	err = service.ValidateDefinition(definition)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition grace period days must be greater than or equal")
}

// TestWorkflowDefinitionService_CountInstances tests the CountInstances method
func TestWorkflowDefinitionService_CountInstances(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create a test definition
	definition := createTestWorkflowDefinition()
	if err := db.Create(definition).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create instances for the definition
	instance1 := createTestWorkflowInstance(definition.ID)
	instance2 := createTestWorkflowInstance(definition.ID)

	if err := db.Create(instance1).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance 1: %v", err)
	}
	if err := db.Create(instance2).Error; err != nil {
		t.Fatalf("Failed to create test workflow instance 2: %v", err)
	}

	// Test count
	count, err := service.CountInstances(definition.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Test count for definition with no instances
	otherDef := createTestWorkflowDefinition()
	if err := db.Create(otherDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	count, err = service.CountInstances(otherDef.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// TestWorkflowDefinitionService_Integration tests integration scenarios
func TestWorkflowDefinitionService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowDefinitionService(db)

	// Create a complete workflow definition with steps and control relationships
	definition := createTestWorkflowDefinition()
	definition.Name = "Complete Test Workflow"
	definition.Description = "A complete workflow for testing"
	definition.SuggestedCadence = "quarterly"

	err := service.Create(definition)
	require.NoError(t, err)

	// Create step definitions
	step1 := createTestWorkflowStepDefinition(definition.ID)
	step1.Name = "Step 1: Initial Assessment"
	step1.ResponsibleRole = "security_analyst"
	step1.EstimatedDuration = 30

	step2 := createTestWorkflowStepDefinition(definition.ID)
	step2.Name = "Step 2: Documentation Review"
	step2.ResponsibleRole = "compliance_officer"
	step2.EstimatedDuration = 45

	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create step 1: %v", err)
	}
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create step 2: %v", err)
	}

	// Create control relationships
	control1 := createTestControlRelationship(definition.ID)
	control1.ControlID = "AC-2"
	control1.ControlSource = "NIST 800-53"

	control2 := createTestControlRelationship(definition.ID)
	control2.ControlID = "IA-1"
	control2.ControlSource = "NIST 800-53"

	if err := db.Create(control1).Error; err != nil {
		t.Fatalf("Failed to create control relationship 1: %v", err)
	}
	if err := db.Create(control2).Error; err != nil {
		t.Fatalf("Failed to create control relationship 2: %v", err)
	}

	// Retrieve the complete definition
	retrieved, err := service.GetByID(definition.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, "Complete Test Workflow", retrieved.Name)
	assert.Len(t, retrieved.Steps, 2)
	assert.Len(t, retrieved.ControlRelationships, 2)

	// Verify step details
	stepNames := make(map[string]bool)
	for _, step := range retrieved.Steps {
		stepNames[step.Name] = true
	}
	assert.True(t, stepNames["Step 1: Initial Assessment"])
	assert.True(t, stepNames["Step 2: Documentation Review"])

	// Verify control relationships
	controlIDs := make(map[string]bool)
	for _, control := range retrieved.ControlRelationships {
		controlIDs[control.ControlID] = true
	}
	assert.True(t, controlIDs["AC-2"])
	assert.True(t, controlIDs["IA-1"])

	// Test updating the definition
	updates := &WorkflowDefinition{
		UUIDModel:   relational.UUIDModel{ID: definition.ID},
		Name:        "Updated Complete Test Workflow",
		Description: "Updated description",
		Version:     "2.0",
	}
	err = service.Update(definition.ID, updates)
	require.NoError(t, err)

	// Verify update
	updated, err := service.GetByID(definition.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Complete Test Workflow", updated.Name)
	assert.Equal(t, "2.0", updated.Version)
	assert.Len(t, updated.Steps, 2)                // Steps should still be there
	assert.Len(t, updated.ControlRelationships, 2) // Control relationships should still be there
}
