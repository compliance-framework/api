package workflows

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestControlRelationshipService_Create tests the Create method
func TestControlRelationshipService_Create(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test workflow definition
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Test successful creation
	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	err := service.Create(relationship)
	require.NoError(t, err)
	assert.NotNil(t, relationship.ID)

	// Verify creation
	var created ControlRelationship
	err = db.First(&created, relationship.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "AC-2", created.ControlID)
	assert.Equal(t, "NIST 800-53 Rev 5", created.ControlSource)
	assert.Equal(t, "satisfies", created.RelationshipType)
	assert.Equal(t, "primary", created.Strength)

	// Test with nil relationship
	err = service.Create(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship cannot be nil")

	// Test with missing workflow definition ID
	invalidRelationship := &ControlRelationship{
		ControlID:        "AC-3",
		ControlSource:    "NIST 800-53 Rev 5",
		RelationshipType: "satisfies",
		Strength:         "primary",
	}
	err = service.Create(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition ID is required")

	// Test with missing control ID
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	err = service.Create(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control ID is required")

	// Test with invalid relationship type
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-4",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "invalid_type",
		Strength:             "primary",
	}
	err = service.Create(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "relationship type")

	// Test with invalid strength
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-5",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "invalid_strength",
	}
	err = service.Create(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "strength")
}

// TestControlRelationshipService_GetByID tests the GetByID method
func TestControlRelationshipService_GetByID(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship).Error)

	// Test successful retrieval
	retrieved, err := service.GetByID(relationship.ID)
	require.NoError(t, err)
	assert.Equal(t, relationship.ID, retrieved.ID)
	assert.Equal(t, "AC-2", retrieved.ControlID)
	assert.NotNil(t, retrieved.WorkflowDefinition)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	_, err = service.GetByID(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestControlRelationshipService_GetByWorkflowDefinitionID tests the GetByWorkflowDefinitionID method
func TestControlRelationshipService_GetByWorkflowDefinitionID(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Create multiple relationships
	relationship1 := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship1).Error)

	relationship2 := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-3",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "partially_satisfies",
		Strength:             "secondary",
	}
	require.NoError(t, db.Create(relationship2).Error)

	// Test retrieval
	relationships, err := service.GetByWorkflowDefinitionID(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, relationships, 2)

	// Test with non-existent workflow definition ID
	nonExistentID := uuid.New()
	relationships, err = service.GetByWorkflowDefinitionID(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, relationships, 0)
}

// TestControlRelationshipService_GetByControlID tests the GetByControlID method
func TestControlRelationshipService_GetByControlID(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef1 := createTestWorkflowDefinition()
	workflowDef1.Name = "Workflow 1"
	require.NoError(t, db.Create(workflowDef1).Error)

	workflowDef2 := createTestWorkflowDefinition()
	workflowDef2.Name = "Workflow 2"
	require.NoError(t, db.Create(workflowDef2).Error)

	// Create relationships with same control ID
	relationship1 := &ControlRelationship{
		WorkflowDefinitionID: workflowDef1.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship1).Error)

	relationship2 := &ControlRelationship{
		WorkflowDefinitionID: workflowDef2.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "supports",
		Strength:             "secondary",
	}
	require.NoError(t, db.Create(relationship2).Error)

	// Test retrieval by control ID
	relationships, err := service.GetByControlID("AC-2")
	require.NoError(t, err)
	assert.Len(t, relationships, 2)
	assert.NotNil(t, relationships[0].WorkflowDefinition)

	// Test with non-existent control ID
	relationships, err = service.GetByControlID("NONEXISTENT")
	require.NoError(t, err)
	assert.Len(t, relationships, 0)
}

// TestControlRelationshipService_GetByControlSource tests the GetByControlSource method
func TestControlRelationshipService_GetByControlSource(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Create relationships with different control sources
	relationship1 := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship1).Error)

	relationship2 := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "A.9.2.5",
		ControlSource:        "ISO 27001",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship2).Error)

	// Test retrieval by control source
	relationships, err := service.GetByControlSource("NIST 800-53 Rev 5")
	require.NoError(t, err)
	assert.Len(t, relationships, 1)
	assert.Equal(t, "AC-2", relationships[0].ControlID)
	assert.NotNil(t, relationships[0].WorkflowDefinition)

	// Test with non-existent control source
	relationships, err = service.GetByControlSource("NONEXISTENT")
	require.NoError(t, err)
	assert.Len(t, relationships, 0)
}

// TestControlRelationshipService_Update tests the Update method
func TestControlRelationshipService_Update(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship).Error)

	// Test successful update
	updates := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-3",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "partially_satisfies",
		Strength:             "secondary",
	}
	err := service.Update(relationship.ID, updates)
	require.NoError(t, err)

	// Verify update
	var updated ControlRelationship
	err = db.First(&updated, relationship.ID).Error
	require.NoError(t, err)
	assert.Equal(t, "AC-3", updated.ControlID)
	assert.Equal(t, "partially_satisfies", updated.RelationshipType)
	assert.Equal(t, "secondary", updated.Strength)

	// Test with nil updates
	err = service.Update(relationship.ID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "updates cannot be nil")

	// Test with non-existent ID
	nonExistentID := uuid.New()
	err = service.Update(&nonExistentID, updates)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestControlRelationshipService_Delete tests the Delete method
func TestControlRelationshipService_Delete(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship).Error)

	// Test successful deletion
	err := service.Delete(relationship.ID)
	require.NoError(t, err)

	// Verify deletion
	var deleted ControlRelationship
	err = db.First(&deleted, relationship.ID).Error
	assert.Error(t, err)

	// Test with non-existent ID
	nonExistentID := uuid.New()
	err = service.Delete(&nonExistentID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship with id")
	assert.Contains(t, err.Error(), "not found")
}

// TestControlRelationshipService_Activate tests the Activate method
func TestControlRelationshipService_Activate(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             false,
	}
	require.NoError(t, db.Create(relationship).Error)

	// Test activation
	err := service.Activate(relationship.ID)
	require.NoError(t, err)

	// Verify activation
	var activated ControlRelationship
	err = db.First(&activated, relationship.ID).Error
	require.NoError(t, err)
	assert.True(t, activated.IsActive)
}

// TestControlRelationshipService_Deactivate tests the Deactivate method
func TestControlRelationshipService_Deactivate(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	require.NoError(t, db.Create(relationship).Error)

	// Test deactivation
	err := service.Deactivate(relationship.ID)
	require.NoError(t, err)

	// Verify deactivation
	var deactivated ControlRelationship
	err = db.First(&deactivated, relationship.ID).Error
	require.NoError(t, err)
	assert.False(t, deactivated.IsActive)
}

// TestControlRelationshipService_ValidateRelationship tests the ValidateRelationship method
func TestControlRelationshipService_ValidateRelationship(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Test valid relationship
	workflowDefID := uuid.New()
	validRelationship := &ControlRelationship{
		WorkflowDefinitionID: &workflowDefID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	err := service.ValidateRelationship(validRelationship)
	assert.NoError(t, err)

	// Test nil relationship
	err = service.ValidateRelationship(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship cannot be nil")

	// Test missing workflow definition ID
	invalidRelationship := &ControlRelationship{
		ControlID:        "AC-2",
		ControlSource:    "NIST 800-53 Rev 5",
		RelationshipType: "satisfies",
		Strength:         "primary",
	}
	err = service.ValidateRelationship(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workflow definition ID is required")

	// Test missing control ID
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: &workflowDefID,
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	err = service.ValidateRelationship(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control ID is required")

	// Test missing control source
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: &workflowDefID,
		ControlID:            "AC-2",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	err = service.ValidateRelationship(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control source is required")

	// Test invalid relationship type
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: &workflowDefID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "invalid",
		Strength:             "primary",
	}
	err = service.ValidateRelationship(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "relationship type")

	// Test invalid strength
	invalidRelationship = &ControlRelationship{
		WorkflowDefinitionID: &workflowDefID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "invalid",
	}
	err = service.ValidateRelationship(invalidRelationship)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "strength")
}

// TestControlRelationshipService_BulkCreate tests the BulkCreate method
func TestControlRelationshipService_BulkCreate(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Test successful bulk creation
	relationships := []ControlRelationship{
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-2",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "satisfies",
			Strength:             "primary",
		},
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-3",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "partially_satisfies",
			Strength:             "secondary",
		},
	}
	err := service.BulkCreate(relationships)
	require.NoError(t, err)

	// Verify creation
	var created []ControlRelationship
	err = db.Where("workflow_definition_id = ?", workflowDef.ID).Find(&created).Error
	require.NoError(t, err)
	assert.Len(t, created, 2)

	// Test with empty slice
	err = service.BulkCreate([]ControlRelationship{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no relationships provided")

	// Test with invalid relationship
	invalidRelationships := []ControlRelationship{
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-4",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "satisfies",
			Strength:             "primary",
		},
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "satisfies",
			Strength:             "primary",
		},
	}
	err = service.BulkCreate(invalidRelationships)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

// TestControlRelationshipService_GetActiveRelationships tests the GetActiveRelationships method
func TestControlRelationshipService_GetActiveRelationships(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Create active and inactive relationships
	activeRelationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	require.NoError(t, db.Create(activeRelationship).Error)

	inactiveRelationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-3",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(inactiveRelationship).Error)
	require.NoError(t, db.Model(inactiveRelationship).Update("is_active", false).Error)

	// Test retrieval of active relationships
	relationships, err := service.GetActiveRelationships(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, relationships, 1)
	assert.Equal(t, "AC-2", relationships[0].ControlID)
	assert.True(t, relationships[0].IsActive)

	// Test with non-existent workflow definition ID
	nonExistentID := uuid.New()
	relationships, err = service.GetActiveRelationships(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, relationships, 0)
}

// TestControlRelationshipService_FindByControlAndSource tests the FindByControlAndSource method
func TestControlRelationshipService_FindByControlAndSource(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
	}
	require.NoError(t, db.Create(relationship).Error)

	// Test successful retrieval
	found, err := service.FindByControlAndSource(workflowDef.ID, "AC-2", "NIST 800-53 Rev 5")
	require.NoError(t, err)
	assert.Equal(t, "AC-2", found.ControlID)
	assert.Equal(t, "NIST 800-53 Rev 5", found.ControlSource)

	// Test with non-existent control
	_, err = service.FindByControlAndSource(workflowDef.ID, "NONEXISTENT", "NIST 800-53 Rev 5")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship not found")

	// Test with non-existent source
	_, err = service.FindByControlAndSource(workflowDef.ID, "AC-2", "NONEXISTENT")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "control relationship not found")
}

// TestControlRelationshipService_GetPrimaryControls tests the GetPrimaryControls method
func TestControlRelationshipService_GetPrimaryControls(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Create relationships with different strengths
	primaryRelationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-2",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	require.NoError(t, db.Create(primaryRelationship).Error)

	secondaryRelationship := &ControlRelationship{
		WorkflowDefinitionID: workflowDef.ID,
		ControlID:            "AC-3",
		ControlSource:        "NIST 800-53 Rev 5",
		RelationshipType:     "partially_satisfies",
		Strength:             "secondary",
		IsActive:             true,
	}
	require.NoError(t, db.Create(secondaryRelationship).Error)

	// Test retrieval of primary controls
	relationships, err := service.GetPrimaryControls(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, relationships, 1)
	assert.Equal(t, "AC-2", relationships[0].ControlID)
	assert.Equal(t, "primary", relationships[0].Strength)

	// Test with non-existent workflow definition ID
	nonExistentID := uuid.New()
	relationships, err = service.GetPrimaryControls(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, relationships, 0)
}

// TestControlRelationshipService_CountControlsBySource tests the CountControlsBySource method
func TestControlRelationshipService_CountControlsBySource(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create test data
	workflowDef := createTestWorkflowDefinition()
	require.NoError(t, db.Create(workflowDef).Error)

	// Create relationships with different sources
	relationships := []ControlRelationship{
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-2",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "satisfies",
			Strength:             "primary",
			IsActive:             true,
		},
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-3",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "satisfies",
			Strength:             "primary",
			IsActive:             true,
		},
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "A.9.2.5",
			ControlSource:        "ISO 27001",
			RelationshipType:     "satisfies",
			Strength:             "primary",
			IsActive:             true,
		},
	}
	for _, rel := range relationships {
		require.NoError(t, db.Create(&rel).Error)
	}

	// Test count by source
	counts, err := service.CountControlsBySource(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, counts, 2)
	assert.Equal(t, int64(2), counts["NIST 800-53 Rev 5"])
	assert.Equal(t, int64(1), counts["ISO 27001"])

	// Test with non-existent workflow definition ID
	nonExistentID := uuid.New()
	counts, err = service.CountControlsBySource(&nonExistentID)
	require.NoError(t, err)
	assert.Len(t, counts, 0)
}

// TestControlRelationshipService_Integration tests integration scenarios
func TestControlRelationshipService_Integration(t *testing.T) {
	db := setupTestDB(t)
	service := NewControlRelationshipService(db)

	// Create workflow definition
	workflowDef := createTestWorkflowDefinition()
	workflowDef.Name = "Access Control Workflow"
	require.NoError(t, db.Create(workflowDef).Error)

	// Scenario: Map multiple controls from different sources
	relationships := []ControlRelationship{
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-2",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "satisfies",
			Strength:             "primary",
			IsActive:             true,
		},
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "AC-3",
			ControlSource:        "NIST 800-53 Rev 5",
			RelationshipType:     "partially_satisfies",
			Strength:             "secondary",
			IsActive:             true,
		},
		{
			WorkflowDefinitionID: workflowDef.ID,
			ControlID:            "A.9.2.1",
			ControlSource:        "ISO 27001",
			RelationshipType:     "satisfies",
			Strength:             "primary",
			IsActive:             true,
		},
	}
	err := service.BulkCreate(relationships)
	require.NoError(t, err)

	// Verify all relationships were created
	allRelationships, err := service.GetByWorkflowDefinitionID(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, allRelationships, 3)

	// Get primary controls
	primaryControls, err := service.GetPrimaryControls(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, primaryControls, 2)

	// Count controls by source
	counts, err := service.CountControlsBySource(workflowDef.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), counts["NIST 800-53 Rev 5"])
	assert.Equal(t, int64(1), counts["ISO 27001"])

	// Find specific control relationship
	found, err := service.FindByControlAndSource(workflowDef.ID, "AC-2", "NIST 800-53 Rev 5")
	require.NoError(t, err)
	assert.Equal(t, "primary", found.Strength)

	// Deactivate a relationship
	err = service.Deactivate(found.ID)
	require.NoError(t, err)

	// Verify only active relationships are returned
	activeRelationships, err := service.GetActiveRelationships(workflowDef.ID)
	require.NoError(t, err)
	assert.Len(t, activeRelationships, 2)

	// Get all relationships for a specific control
	ac2Relationships, err := service.GetByControlID("AC-2")
	require.NoError(t, err)
	assert.Len(t, ac2Relationships, 1)
	assert.False(t, ac2Relationships[0].IsActive)

	// Get all relationships for a specific source
	nistRelationships, err := service.GetByControlSource("NIST 800-53 Rev 5")
	require.NoError(t, err)
	assert.Len(t, nistRelationships, 2)
}
