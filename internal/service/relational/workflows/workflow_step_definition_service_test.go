package workflows

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestWorkflowStepDefinitionService_Create tests the Create method
func TestWorkflowStepDefinitionService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition first
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Test successful creation
	step := createTestWorkflowStepDefinition(workflowDef.ID)
	err := service.Create(step)
	require.NoError(t, err)
	require.NotNil(t, step.ID)

	// Verify in database
	var found WorkflowStepDefinition
	err = db.First(&found, step.ID).Error
	require.NoError(t, err)
	assert.Equal(t, step.Name, found.Name)

	// Test with nil step
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step definition cannot be nil")

	// Test with empty name
	invalidStep := createTestWorkflowStepDefinition(workflowDef.ID)
	invalidStep.Name = ""
	err = service.Create(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step name is required")

	// Test with empty responsible role
	invalidStep = createTestWorkflowStepDefinition(workflowDef.ID)
	invalidStep.ResponsibleRole = ""
	err = service.Create(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "responsible role is required")

	// Test with nil workflow definition ID
	invalidStep = createTestWorkflowStepDefinition(nil)
	err = service.Create(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition ID is required")
}

// TestWorkflowStepDefinitionService_GetByID tests the GetByID method
func TestWorkflowStepDefinitionService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and step
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step := createTestWorkflowStepDefinition(workflowDef.ID)
	if err := db.Create(step).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition: %v", err)
	}

	// Test successful retrieval
	retrieved, err := service.GetByID(step.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, step.Name, retrieved.Name)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	retrieved, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "workflow step definition with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowStepDefinitionService_GetByWorkflowDefinitionID tests the GetByWorkflowDefinitionID method
func TestWorkflowStepDefinitionService_GetByWorkflowDefinitionID(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create multiple steps for the workflow
	steps := []*WorkflowStepDefinition{
		createTestWorkflowStepDefinition(workflowDef.ID),
		createTestWorkflowStepDefinition(workflowDef.ID),
		createTestWorkflowStepDefinition(workflowDef.ID),
	}

	for i, step := range steps {
		step.Name = "Step " + string(rune('A'+i))
		if err := db.Create(step).Error; err != nil {
			t.Fatalf("Failed to create test workflow step definition %d: %v", i, err)
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

// TestWorkflowStepDefinitionService_Update tests the Update method
func TestWorkflowStepDefinitionService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and step
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step := createTestWorkflowStepDefinition(workflowDef.ID)
	if err := db.Create(step).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition: %v", err)
	}

	// Test successful update
	updates := &WorkflowStepDefinition{
		UUIDModel:            relational.UUIDModel{ID: step.ID},
		WorkflowDefinitionID: step.WorkflowDefinitionID,
		Name:                 "Updated Step Definition",
		Description:          "Updated description",
		ResponsibleRole:      "updated_role",
		EstimatedDuration:    120,
	}
	err := service.Update(step.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated WorkflowStepDefinition
	err = db.First(&updated, step.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "Updated Step Definition", updated.Name)
	assert.Equal(t, "updated_role", updated.ResponsibleRole)
	assert.Equal(t, 120, updated.EstimatedDuration)

	// Test with nil updates
	err = service.Update(step.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	updatesWithNonExistentID := &WorkflowStepDefinition{
		UUIDModel:            relational.UUIDModel{ID: &nonExistentID},
		WorkflowDefinitionID: workflowDef.ID, // Include the workflow definition ID
		Name:                 "Updated Step Definition",
		ResponsibleRole:      "updated_role",
	}
	err = service.Update(&nonExistentID, updatesWithNonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step definition with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestWorkflowStepDefinitionService_Delete tests the Delete method
func TestWorkflowStepDefinitionService_Delete(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and step
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step := createTestWorkflowStepDefinition(workflowDef.ID)
	if err := db.Create(step).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition: %v", err)
	}

	// Test successful deletion
	err := service.Delete(step.ID)
	require.NoError(t, err)

	// Verify soft deletion
	var deleted WorkflowStepDefinition
	err = db.Unscoped().First(&deleted, step.ID).Error
	require.NoError(t, err)
	assert.NotNil(t, deleted.DeletedAt)

	// Verify it's not found with normal query
	var notFound WorkflowStepDefinition
	err = db.First(&notFound, step.ID).Error
	assert.Error(t, err)
	assert.Equal(t, gorm.ErrRecordNotFound, err)

	// Test deletion of non-existent step
	nonExistentID := uuid.New()
	err = service.Delete(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step definition with id")
	assert.Contains(t, err.Error(), "not found")

	// Test deletion of step with dependencies
	stepWithDeps := createTestWorkflowStepDefinition(workflowDef.ID)
	if err := db.Create(stepWithDeps).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition: %v", err)
	}

	dependentStep := createTestWorkflowStepDefinition(workflowDef.ID)
	if err := db.Create(dependentStep).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition: %v", err)
	}

	// Add dependency
	err = service.AddDependency(dependentStep.ID, stepWithDeps.ID)
	require.NoError(t, err)

	// Try to delete step that has dependencies
	err = service.Delete(stepWithDeps.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete step: 1 other steps depend on it")
}

// TestWorkflowStepDefinitionService_AddDependency tests the AddDependency method
func TestWorkflowStepDefinitionService_AddDependency(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and steps
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Step 1"
	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 1: %v", err)
	}

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Step 2"
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 2: %v", err)
	}

	// Test successful dependency addition
	err := service.AddDependency(step2.ID, step1.ID)
	require.NoError(t, err)

	// Verify dependency exists
	dependencies, err := service.GetDependencies(step2.ID)
	require.NoError(t, err)
	assert.Len(t, dependencies, 1)
	assert.Equal(t, step1.ID, dependencies[0].ID)

	// Test adding duplicate dependency
	err = service.AddDependency(step2.ID, step1.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dependency already exists")

	// Test with non-existent step
	nonExistentID := uuid.New()
	err = service.AddDependency(&nonExistentID, step1.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step not found")

	err = service.AddDependency(step1.ID, &nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "depends on step not found")
}

// TestWorkflowStepDefinitionService_RemoveDependency tests the RemoveDependency method
func TestWorkflowStepDefinitionService_RemoveDependency(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and steps
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Step 1"
	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 1: %v", err)
	}

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Step 2"
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 2: %v", err)
	}

	// Add dependency first
	err := service.AddDependency(step2.ID, step1.ID)
	require.NoError(t, err)

	// Test successful dependency removal
	err = service.RemoveDependency(step2.ID, step1.ID)
	require.NoError(t, err)

	// Verify dependency is removed
	dependencies, err := service.GetDependencies(step2.ID)
	require.NoError(t, err)
	assert.Len(t, dependencies, 0)

	// Test removing non-existent dependency
	err = service.RemoveDependency(step2.ID, step1.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dependency not found")
}

// TestWorkflowStepDefinitionService_GetDependencies tests the GetDependencies method
func TestWorkflowStepDefinitionService_GetDependencies(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and steps
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Step 1"
	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 1: %v", err)
	}

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Step 2"
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 2: %v", err)
	}

	step3 := createTestWorkflowStepDefinition(workflowDef.ID)
	step3.Name = "Step 3"
	if err := db.Create(step3).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 3: %v", err)
	}

	// Add dependencies: step3 depends on step1 and step2
	err := service.AddDependency(step3.ID, step1.ID)
	require.NoError(t, err)
	err = service.AddDependency(step3.ID, step2.ID)
	require.NoError(t, err)

	// Test getting dependencies
	dependencies, err := service.GetDependencies(step3.ID)
	require.NoError(t, err)
	assert.Len(t, dependencies, 2)

	// Verify dependency names
	depNames := make(map[string]bool)
	for _, dep := range dependencies {
		depNames[dep.Name] = true
	}
	assert.True(t, depNames["Step 1"])
	assert.True(t, depNames["Step 2"])

	// Test getting dependencies for step with no dependencies
	noDeps, err := service.GetDependencies(step1.ID)
	require.NoError(t, err)
	assert.Len(t, noDeps, 0)
}

// TestWorkflowStepDefinitionService_GetDependentSteps tests the GetDependentSteps method
func TestWorkflowStepDefinitionService_GetDependentSteps(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and steps
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Step 1"
	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 1: %v", err)
	}

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Step 2"
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 2: %v", err)
	}

	step3 := createTestWorkflowStepDefinition(workflowDef.ID)
	step3.Name = "Step 3"
	if err := db.Create(step3).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 3: %v", err)
	}

	// Add dependencies: step2 and step3 depend on step1
	err := service.AddDependency(step2.ID, step1.ID)
	require.NoError(t, err)
	err = service.AddDependency(step3.ID, step1.ID)
	require.NoError(t, err)

	// Test getting dependent steps
	dependents, err := service.GetDependentSteps(step1.ID)
	require.NoError(t, err)
	assert.Len(t, dependents, 2)

	// Verify dependent names
	depNames := make(map[string]bool)
	for _, dep := range dependents {
		depNames[dep.Name] = true
	}
	assert.True(t, depNames["Step 2"])
	assert.True(t, depNames["Step 3"])

	// Test getting dependents for step with no dependents
	noDependents, err := service.GetDependentSteps(step2.ID)
	require.NoError(t, err)
	assert.Len(t, noDependents, 0)
}

// TestWorkflowStepDefinitionService_HasCircularDependency tests the HasCircularDependency method
func TestWorkflowStepDefinitionService_HasCircularDependency(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition and steps
	workflowDef := createTestWorkflowDefinition()
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Step 1"
	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 1: %v", err)
	}

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Step 2"
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 2: %v", err)
	}

	step3 := createTestWorkflowStepDefinition(workflowDef.ID)
	step3.Name = "Step 3"
	if err := db.Create(step3).Error; err != nil {
		t.Fatalf("Failed to create test workflow step definition 3: %v", err)
	}

	// Test no circular dependency
	hasCycle, err := service.HasCircularDependency(step2.ID, step1.ID)
	require.NoError(t, err)
	assert.False(t, hasCycle)

	// Create a chain: step1 -> step2 -> step3
	err = service.AddDependency(step2.ID, step1.ID)
	require.NoError(t, err)
	err = service.AddDependency(step3.ID, step2.ID)
	require.NoError(t, err)

	// Test adding step3 -> step1 would create a cycle
	hasCycle, err = service.HasCircularDependency(step1.ID, step3.ID)
	require.NoError(t, err)
	assert.True(t, hasCycle)

	// Test adding step1 -> step3 would not create a cycle (already exists in reverse)
	hasCycle, err = service.HasCircularDependency(step3.ID, step1.ID)
	require.NoError(t, err)
	assert.False(t, hasCycle)
}

// TestWorkflowStepDefinitionService_ValidateStep tests the ValidateStep method
func TestWorkflowStepDefinitionService_ValidateStep(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Test valid step
	testUUID := uuid.New()
	validStep := createTestWorkflowStepDefinition(&testUUID)
	err := service.ValidateStep(validStep)
	assert.NoError(t, err)

	// Test nil step
	err = service.ValidateStep(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step definition cannot be nil")

	// Test empty name
	testUUID2 := uuid.New()
	invalidStep := createTestWorkflowStepDefinition(&testUUID2)
	invalidStep.Name = ""
	err = service.ValidateStep(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step name is required")

	// Test name too long
	testUUID3 := uuid.New()
	invalidStep = createTestWorkflowStepDefinition(&testUUID3)
	invalidStep.Name = string(make([]byte, MaxNameLength+1))
	err = service.ValidateStep(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "step name cannot exceed")

	// Test empty responsible role
	testUUID4 := uuid.New()
	invalidStep = createTestWorkflowStepDefinition(&testUUID4)
	invalidStep.ResponsibleRole = ""
	err = service.ValidateStep(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "responsible role is required")

	// Test responsible role too long
	testUUID5 := uuid.New()
	invalidStep = createTestWorkflowStepDefinition(&testUUID5)
	invalidStep.ResponsibleRole = string(make([]byte, MaxRoleNameLength+1))
	err = service.ValidateStep(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "responsible role cannot exceed")

	// Test nil workflow definition ID
	invalidStep = createTestWorkflowStepDefinition(nil)
	err = service.ValidateStep(invalidStep)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition ID is required")
}

func TestWorkflowStepDefinitionService_ValidateStepGracePeriodHierarchy(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	missingDefinitionID := uuid.New()
	missingDefinitionGrace := 1
	missingDefinitionStep := createTestWorkflowStepDefinition(&missingDefinitionID)
	missingDefinitionStep.GracePeriodDays = &missingDefinitionGrace

	err := service.ValidateStep(missingDefinitionStep)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition not found")

	definitionGrace := 5
	definition := createTestWorkflowDefinition()
	definition.GracePeriodDays = &definitionGrace
	require.NoError(t, db.Create(definition).Error)

	stepGrace := 6
	step := createTestWorkflowStepDefinition(definition.ID)
	step.GracePeriodDays = &stepGrace

	err = service.ValidateStep(step)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step grace period days must be less than or equal")

	stepGrace = 4
	step.GracePeriodDays = &stepGrace
	instanceGrace := 3
	instance := createTestWorkflowInstance(definition.ID)
	instance.GracePeriodDays = &instanceGrace
	require.NoError(t, db.Create(instance).Error)

	err = service.ValidateStep(step)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workflow step grace period days must be less than or equal")
}

// TestWorkflowStepDefinitionService_Integration tests integration scenarios
func TestWorkflowStepDefinitionService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewWorkflowStepDefinitionService(db)

	// Create a workflow definition
	workflowDef := createTestWorkflowDefinition()
	workflowDef.Name = "Complex Workflow"
	if err := db.Create(workflowDef).Error; err != nil {
		t.Fatalf("Failed to create test workflow definition: %v", err)
	}

	// Create multiple steps with complex dependencies
	step1 := createTestWorkflowStepDefinition(workflowDef.ID)
	step1.Name = "Initial Assessment"
	step1.ResponsibleRole = "security_analyst"
	step1.EstimatedDuration = 30

	step2 := createTestWorkflowStepDefinition(workflowDef.ID)
	step2.Name = "Documentation Review"
	step2.ResponsibleRole = "compliance_officer"
	step2.EstimatedDuration = 45

	step3 := createTestWorkflowStepDefinition(workflowDef.ID)
	step3.Name = "Final Approval"
	step3.ResponsibleRole = "manager"
	step3.EstimatedDuration = 15

	// Create steps
	if err := db.Create(step1).Error; err != nil {
		t.Fatalf("Failed to create step 1: %v", err)
	}
	if err := db.Create(step2).Error; err != nil {
		t.Fatalf("Failed to create step 2: %v", err)
	}
	if err := db.Create(step3).Error; err != nil {
		t.Fatalf("Failed to create step 3: %v", err)
	}

	// Add dependencies: step2 depends on step1, step3 depends on step2
	err := service.AddDependency(step2.ID, step1.ID)
	require.NoError(t, err)
	err = service.AddDependency(step3.ID, step2.ID)
	require.NoError(t, err)

	// Retrieve all steps for the workflow
	steps, err := service.GetByWorkflowDefinitionID(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, steps, 3)

	// Verify dependency structure
	step2Dependencies, err := service.GetDependencies(step2.ID)
	require.NoError(t, err)
	assert.Len(t, step2Dependencies, 1)
	assert.Equal(t, step1.ID, step2Dependencies[0].ID)

	step3Dependencies, err := service.GetDependencies(step3.ID)
	require.NoError(t, err)
	assert.Len(t, step3Dependencies, 1)
	assert.Equal(t, step2.ID, step3Dependencies[0].ID)

	// Test circular dependency detection
	hasCycle, err := service.HasCircularDependency(step1.ID, step3.ID)
	require.NoError(t, err)
	assert.True(t, hasCycle) // step1 -> step2 -> step3 -> step1 would create a cycle

	// Update step details
	updates := &WorkflowStepDefinition{
		UUIDModel:            relational.UUIDModel{ID: step1.ID},
		WorkflowDefinitionID: step1.WorkflowDefinitionID, // Include the workflow definition ID
		Name:                 "Enhanced Initial Assessment",
		Description:          "Updated with more comprehensive checks",
		ResponsibleRole:      step1.ResponsibleRole, // Keep the original responsible role
		EstimatedDuration:    45,
	}
	err = service.Update(step1.ID, updates)
	require.NoError(t, err)

	// Verify update
	updated, err := service.GetByID(step1.ID)
	require.NoError(t, err)
	assert.Equal(t, "Enhanced Initial Assessment", updated.Name)
	assert.Equal(t, 45, updated.EstimatedDuration)

	// Verify dependencies are still intact after update
	dependencies, err := service.GetDependencies(step2.ID)
	require.NoError(t, err)
	assert.Len(t, dependencies, 1)
	assert.Equal(t, step1.ID, dependencies[0].ID)
}
