package workflows

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupFilterSyncTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	for _, entity := range GetWorkflowEntities() {
		require.NoError(t, db.AutoMigrate(entity))
	}
	require.NoError(t, db.AutoMigrate(
		&relational.Control{},
		&relational.Filter{},
	))

	return db
}

func TestFilterSyncService_SyncFilterForDefinition(t *testing.T) {
	db := setupFilterSyncTestDB(t)
	service := NewFilterSyncService(db, zap.NewNop().Sugar())

	definition := createTestWorkflowDefinition()
	require.NoError(t, db.Create(definition).Error)

	catalogID1 := uuid.New()
	catalogID2 := uuid.New()
	control1 := relational.Control{CatalogID: catalogID1, ID: "ctrl-1", Title: "Control 1"}
	control2 := relational.Control{CatalogID: catalogID2, ID: "ctrl-1", Title: "Control 1 in another catalog"}
	control3 := relational.Control{CatalogID: catalogID1, ID: "ctrl-2", Title: "Control 2"}
	require.NoError(t, db.Create(&control1).Error)
	require.NoError(t, db.Create(&control2).Error)
	require.NoError(t, db.Create(&control3).Error)

	relationship1 := &ControlRelationship{
		WorkflowDefinitionID: definition.ID,
		ControlID:            control1.ID,
		ControlSource:        "test catalog",
		CatalogID:            catalogID1.String(),
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	inactiveRelationship := &ControlRelationship{
		WorkflowDefinitionID: definition.ID,
		ControlID:            control2.ID,
		ControlSource:        "other catalog",
		CatalogID:            catalogID2.String(),
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             false,
	}
	require.NoError(t, db.Create(relationship1).Error)
	require.NoError(t, db.Create(inactiveRelationship).Error)
	require.NoError(t, db.Model(inactiveRelationship).Update("is_active", false).Error)

	require.NoError(t, service.SyncFilterForDefinition(*definition.ID))
	filterID := generateWorkflowFilterUUID(*definition.ID)

	var filter relational.Filter
	require.NoError(t, db.Preload("Controls").First(&filter, "id = ?", filterID).Error)
	require.Equal(t, "Workflow: "+definition.Name, filter.Name)
	require.Len(t, filter.Controls, 1)
	require.Equal(t, catalogID1, filter.Controls[0].CatalogID)
	require.Equal(t, "ctrl-1", filter.Controls[0].ID)
	require.Equal(t, WorkflowEvidencePolicyLabel, filter.Filter.Data().Scope.Label)
	require.Equal(t, WorkflowPolicyValue(*definition.ID), filter.Filter.Data().Scope.Value)

	require.NoError(t, service.SyncFilterForDefinition(*definition.ID))
	var filterCount int64
	require.NoError(t, db.Model(&relational.Filter{}).Where("id = ?", filterID).Count(&filterCount).Error)
	require.Equal(t, int64(1), filterCount)

	relationship2 := &ControlRelationship{
		WorkflowDefinitionID: definition.ID,
		ControlID:            control3.ID,
		ControlSource:        "test catalog",
		CatalogID:            catalogID1.String(),
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	require.NoError(t, db.Create(relationship2).Error)
	require.NoError(t, service.SyncFilterForDefinition(*definition.ID))

	require.NoError(t, db.Preload("Controls").First(&filter, "id = ?", filterID).Error)
	require.Len(t, filter.Controls, 2)

	require.NoError(t, db.Delete(relationship2).Error)
	require.NoError(t, service.SyncFilterForDefinition(*definition.ID))
	require.NoError(t, db.Preload("Controls").First(&filter, "id = ?", filterID).Error)
	require.Len(t, filter.Controls, 1)
	require.Equal(t, "ctrl-1", filter.Controls[0].ID)

	require.NoError(t, db.Model(relationship1).Update("is_active", false).Error)
	require.NoError(t, service.SyncFilterForDefinition(*definition.ID))
	require.NoError(t, db.Preload("Controls").First(&filter, "id = ?", filterID).Error)
	require.Empty(t, filter.Controls)
}

func TestFilterSyncService_DeleteFilterForDefinition(t *testing.T) {
	db := setupFilterSyncTestDB(t)
	service := NewFilterSyncService(db, zap.NewNop().Sugar())

	definition := createTestWorkflowDefinition()
	require.NoError(t, db.Create(definition).Error)

	catalogID := uuid.New()
	control := relational.Control{CatalogID: catalogID, ID: "ctrl-1", Title: "Control 1"}
	require.NoError(t, db.Create(&control).Error)

	relationship := &ControlRelationship{
		WorkflowDefinitionID: definition.ID,
		ControlID:            control.ID,
		ControlSource:        "test catalog",
		CatalogID:            catalogID.String(),
		RelationshipType:     "satisfies",
		Strength:             "primary",
		IsActive:             true,
	}
	require.NoError(t, db.Create(relationship).Error)
	require.NoError(t, service.SyncFilterForDefinition(*definition.ID))

	filterID := generateWorkflowFilterUUID(*definition.ID)
	var joinCount int64
	require.NoError(t, db.Table("filter_controls").Where("filter_id = ?", filterID).Count(&joinCount).Error)
	require.Equal(t, int64(1), joinCount)

	require.NoError(t, service.DeleteFilterForDefinition(*definition.ID))

	var filterCount int64
	require.NoError(t, db.Model(&relational.Filter{}).Where("id = ?", filterID).Count(&filterCount).Error)
	require.Equal(t, int64(0), filterCount)
	require.NoError(t, db.Table("filter_controls").Where("filter_id = ?", filterID).Count(&joinCount).Error)
	require.Equal(t, int64(0), joinCount)

	require.NoError(t, service.DeleteFilterForDefinition(*definition.ID))
}
