package workflows

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleAssignmentService_Create tests the Create method
func TestRoleAssignmentService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test workflow instance
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Test successful creation
	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           true,
	}
	err := service.Create(assignment)
	require.NoError(t, err)
	assert.NotNil(t, assignment.ID)

	// Verify creation
	var created RoleAssignment
	err = db.First(&created, assignment.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "reviewer", created.RoleName)
	assert.Equal(t, "user", created.AssignedToType)
	assert.Equal(t, "user123", created.AssignedToID)

	// Test with nil assignment
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment cannot be nil")

	// Test with missing workflow instance ID
	invalidAssignment := &RoleAssignment{
		RoleName:       "reviewer",
		AssignedToType: "user",
		AssignedToID:   "user123",
	}
	err = service.Create(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance ID is required")

	// Test with missing role name
	invalidAssignment = &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	err = service.Create(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role name is required")

	// Test with invalid assignment type
	invalidAssignment = &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "invalid",
		AssignedToID:       "user123",
	}
	err = service.Create(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assigned to type")
}

// TestRoleAssignmentService_GetByID tests the GetByID method
func TestRoleAssignmentService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test successful retrieval
	retrieved, err := service.GetByID(assignment.ID)
	require.NoError(t, err)
	assert.Equal(t, assignment.ID, retrieved.ID)
	assert.Equal(t, "reviewer", retrieved.RoleName)
	assert.NotNil(t, retrieved.WorkflowInstance)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	_, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestRoleAssignmentService_GetByWorkflowInstanceID tests the GetByWorkflowInstanceID method
func TestRoleAssignmentService_GetByWorkflowInstanceID(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Create multiple assignments
	assignment1 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	require.NoError(t, db.Create(assignment1).Error)

	assignment2 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "approver",
		AssignedToType:     "group",
		AssignedToID:       "group456",
	}
	require.NoError(t, db.Create(assignment2).Error)

	// Test retrieval
	assignments, err := service.GetByWorkflowInstanceID(instance.ID)
	require.NoError(t, err)
	assert.Len(t, assignments, 2)

	// Test with non-existent instance ID
	nonExistentID := uuid.New()
	assignments, err = service.GetByWorkflowInstanceID(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, assignments, 0)
}

// TestRoleAssignmentService_GetByRole tests the GetByRole method
func TestRoleAssignmentService_GetByRole(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Create assignments with different roles
	assignment1 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	require.NoError(t, db.Create(assignment1).Error)

	assignment2 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "approver",
		AssignedToType:     "user",
		AssignedToID:       "user456",
	}
	require.NoError(t, db.Create(assignment2).Error)

	// Test retrieval by role
	assignments, err := service.GetByRole(instance.ID, "reviewer")
	require.NoError(t, err)
	assert.Len(t, assignments, 1)
	assert.Equal(t, "reviewer", assignments[0].RoleName)

	// Test with non-existent role
	assignments, err = service.GetByRole(instance.ID, "nonexistent")
	require.NoError(t, err)
	assert.Len(t, assignments, 0)
}

// TestRoleAssignmentService_GetByAssignee tests the GetByAssignee method
func TestRoleAssignmentService_GetByAssignee(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Create assignments for different assignees
	assignment1 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           true,
	}
	require.NoError(t, db.Create(assignment1).Error)

	assignment2 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "approver",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           true,
	}
	require.NoError(t, db.Create(assignment2).Error)

	assignment3 := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user456",
		IsActive:           true,
	}
	require.NoError(t, db.Create(assignment3).Error)

	// Test retrieval by assignee
	assignments, err := service.GetByAssignee("user", "user123")
	require.NoError(t, err)
	assert.Len(t, assignments, 2)
	assert.NotNil(t, assignments[0].WorkflowInstance)

	// Test with non-existent assignee
	assignments, err = service.GetByAssignee("user", "nonexistent")
	require.NoError(t, err)
	assert.Len(t, assignments, 0)
}

// TestRoleAssignmentService_Update tests the Update method
func TestRoleAssignmentService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test successful update
	updates := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "approver",
		AssignedToType:     "group",
		AssignedToID:       "group456",
	}
	err := service.Update(assignment.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated RoleAssignment
	err = db.First(&updated, assignment.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "approver", updated.RoleName)
	assert.Equal(t, "group", updated.AssignedToType)
	assert.Equal(t, "group456", updated.AssignedToID)

	// Test with nil updates
	err = service.Update(assignment.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	err = service.Update(&nonExistentID, updates)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestRoleAssignmentService_Delete tests the Delete method
func TestRoleAssignmentService_Delete(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test successful deletion
	err := service.Delete(assignment.ID)
	require.NoError(t, err)

	// Verify deletion
	var deleted RoleAssignment
	err = db.First(&deleted, assignment.ID).Error
	assert.Error(t, err)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	err = service.Delete(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestRoleAssignmentService_Activate tests the Activate method
func TestRoleAssignmentService_Activate(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           false,
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test activation
	err := service.Activate(assignment.ID)
	require.NoError(t, err)

	// Verify activation
	var activated RoleAssignment
	err = db.First(&activated, assignment.ID).Error
	require.NoError(t, err)
	assert.True(t, activated.IsActive)
}

// TestRoleAssignmentService_Deactivate tests the Deactivate method
func TestRoleAssignmentService_Deactivate(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           true,
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test deactivation
	err := service.Deactivate(assignment.ID)
	require.NoError(t, err)

	// Verify deactivation
	var deactivated RoleAssignment
	err = db.First(&deactivated, assignment.ID).Error
	require.NoError(t, err)
	assert.False(t, deactivated.IsActive)
}

// TestRoleAssignmentService_ReassignRole tests the ReassignRole method
func TestRoleAssignmentService_ReassignRole(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test successful reassignment
	err := service.ReassignRole(assignment.ID, "group", "group456")
	require.NoError(t, err)

	// Verify reassignment
	var reassigned RoleAssignment
	err = db.First(&reassigned, assignment.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "group", reassigned.AssignedToType)
	assert.Equal(t, "group456", reassigned.AssignedToID)

	// Test with empty assigned to type
	err = service.ReassignRole(assignment.ID, "", "user789")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assigned to type is required")

	// Test with empty assigned to ID
	err = service.ReassignRole(assignment.ID, "user", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assigned to ID is required")

	// Test with invalid assignment type
	err = service.ReassignRole(assignment.ID, "invalid", "user789")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assigned to type")
}

// TestRoleAssignmentService_ValidateAssignment tests the ValidateAssignment method
func TestRoleAssignmentService_ValidateAssignment(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Test valid assignment
	instanceID := uuid.New()
	validAssignment := &RoleAssignment{
		WorkflowInstanceID: &instanceID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	err := service.ValidateAssignment(validAssignment)
	assert.NoError(t, err)

	// Test nil assignment
	err = service.ValidateAssignment(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role assignment cannot be nil")

	// Test missing workflow instance ID
	invalidAssignment := &RoleAssignment{
		RoleName:       "reviewer",
		AssignedToType: "user",
		AssignedToID:   "user123",
	}
	err = service.ValidateAssignment(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow instance ID is required")

	// Test missing role name
	invalidAssignment = &RoleAssignment{
		WorkflowInstanceID: &instanceID,
		AssignedToType:     "user",
		AssignedToID:       "user123",
	}
	err = service.ValidateAssignment(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "role name is required")

	// Test invalid assignment type
	invalidAssignment = &RoleAssignment{
		WorkflowInstanceID: &instanceID,
		RoleName:           "reviewer",
		AssignedToType:     "invalid",
		AssignedToID:       "user123",
	}
	err = service.ValidateAssignment(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assigned to type")

	// Test missing assigned to ID
	invalidAssignment = &RoleAssignment{
		WorkflowInstanceID: &instanceID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
	}
	err = service.ValidateAssignment(invalidAssignment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "assigned to ID is required")
}

// TestRoleAssignmentService_BulkCreate tests the BulkCreate method
func TestRoleAssignmentService_BulkCreate(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Test successful bulk creation
	assignments := []RoleAssignment{
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "reviewer",
			AssignedToType:     "user",
			AssignedToID:       "user123",
		},
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "approver",
			AssignedToType:     "group",
			AssignedToID:       "group456",
		},
	}
	err := service.BulkCreate(assignments)
	require.NoError(t, err)

	// Verify creation
	var created []RoleAssignment
	err = db.Where("workflow_instance_id = ?", instance.ID).Find(&created).Error
	require.NoError(t, err)
	assert.Len(t, created, 2)

	// Test with empty slice
	err = service.BulkCreate([]RoleAssignment{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no assignments provided")

	// Test with invalid assignment
	invalidAssignments := []RoleAssignment{
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "reviewer",
			AssignedToType:     "user",
			AssignedToID:       "user789",
		},
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "",
			AssignedToType:     "user",
			AssignedToID:       "user999",
		},
	}
	err = service.BulkCreate(invalidAssignments)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

// TestRoleAssignmentService_GetActiveAssignments tests the GetActiveAssignments method
func TestRoleAssignmentService_GetActiveAssignments(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Create active and inactive assignments
	activeAssignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           true,
	}
	require.NoError(t, db.Create(activeAssignment).Error)

	inactiveAssignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "approver",
		AssignedToType:     "user",
		AssignedToID:       "user456",
	}
	require.NoError(t, db.Create(inactiveAssignment).Error)
	// Explicitly set to inactive after creation
	require.NoError(t, db.Model(inactiveAssignment).Update("is_active", false).Error)

	// Test retrieval of active assignments
	assignments, err := service.GetActiveAssignments(instance.ID)
	require.NoError(t, err)
	assert.Len(t, assignments, 1)
	assert.Equal(t, "reviewer", assignments[0].RoleName)
	assert.True(t, assignments[0].IsActive)

	// Test with non-existent instance ID
	nonExistentID := uuid.New()
	assignments, err = service.GetActiveAssignments(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, assignments, 0)
}

// TestRoleAssignmentService_FindAssigneeForRole tests the FindAssigneeForRole method
func TestRoleAssignmentService_FindAssigneeForRole(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	require.NoError(t, db.Create(instance).Error)

	// Create active assignment
	assignment := &RoleAssignment{
		WorkflowInstanceID: instance.ID,
		RoleName:           "reviewer",
		AssignedToType:     "user",
		AssignedToID:       "user123",
		IsActive:           true,
	}
	require.NoError(t, db.Create(assignment).Error)

	// Test successful retrieval
	found, err := service.FindAssigneeForRole(instance.ID, "reviewer")
	require.NoError(t, err)
	assert.Equal(t, "reviewer", found.RoleName)
	assert.Equal(t, "user123", found.AssignedToID)

	// Test with non-existent role
	_, err = service.FindAssigneeForRole(instance.ID, "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active assignment found for role")

	// Test with inactive assignment
	require.NoError(t, db.Model(assignment).Update("is_active", false).Error)
	_, err = service.FindAssigneeForRole(instance.ID, "reviewer")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no active assignment found for role")
}

// TestRoleAssignmentService_Integration tests integration scenarios
func TestRoleAssignmentService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewRoleAssignmentService(db)

	// Create workflow definition and instance
	workflowDef := createTestWorkflowDefinition()
	workflowDef.Name = "Security Review Workflow"
	require.NoError(t, db.Create(workflowDef).Error)

	instance := createTestWorkflowInstance(workflowDef.ID)
	instance.Name = "Q1 Security Review"
	require.NoError(t, db.Create(instance).Error)

	// Scenario: Assign multiple roles to different users
	assignments := []RoleAssignment{
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "security_analyst",
			AssignedToType:     "user",
			AssignedToID:       "analyst1",
			IsActive:           true,
		},
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "security_reviewer",
			AssignedToType:     "user",
			AssignedToID:       "reviewer1",
			IsActive:           true,
		},
		{
			WorkflowInstanceID: instance.ID,
			RoleName:           "security_approver",
			AssignedToType:     "group",
			AssignedToID:       "security_team",
			IsActive:           true,
		},
	}
	err := service.BulkCreate(assignments)
	require.NoError(t, err)

	// Verify all assignments were created
	allAssignments, err := service.GetByWorkflowInstanceID(instance.ID)
	require.NoError(t, err)
	assert.Len(t, allAssignments, 3)

	// Find specific role assignee
	analystAssignment, err := service.FindAssigneeForRole(instance.ID, "security_analyst")
	require.NoError(t, err)
	assert.Equal(t, "analyst1", analystAssignment.AssignedToID)

	// Reassign a role
	err = service.ReassignRole(analystAssignment.ID, "user", "analyst2")
	require.NoError(t, err)

	// Verify reassignment
	updatedAssignment, err := service.GetByID(analystAssignment.ID)
	require.NoError(t, err)
	assert.Equal(t, "analyst2", updatedAssignment.AssignedToID)

	// Deactivate a role
	reviewerAssignments, err := service.GetByRole(instance.ID, "security_reviewer")
	require.NoError(t, err)
	require.Len(t, reviewerAssignments, 1)

	err = service.Deactivate(reviewerAssignments[0].ID)
	require.NoError(t, err)

	// Verify only active assignments are returned
	activeAssignments, err := service.GetActiveAssignments(instance.ID)
	require.NoError(t, err)
	assert.Len(t, activeAssignments, 2)

	// Get all assignments for a specific user
	userAssignments, err := service.GetByAssignee("user", "analyst2")
	require.NoError(t, err)
	assert.Len(t, userAssignments, 1)
	assert.Equal(t, "security_analyst", userAssignments[0].RoleName)
}
