package workflows

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupWorkflowSeedTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("failed to get sql.DB handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	for _, entity := range GetWorkflowEntities() {
		if err := db.AutoMigrate(entity); err != nil {
			t.Fatalf("failed to migrate %T: %v", entity, err)
		}
	}
	if err := db.AutoMigrate(&relational.Control{}, &relational.Filter{}); err != nil {
		t.Fatalf("failed to migrate filter entities: %v", err)
	}

	return db
}

func TestImportWorkflowsFromFile(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)
	sugar := zap.NewNop().Sugar()
	seedWorkflowFilterControl(t, db)

	summary, err := importWorkflowsFromFileForTest(context.Background(), db, sugar, "../../../../cmd/seed/testdata/soc2_workflows.sample.json")
	if err != nil {
		t.Fatalf("importWorkflowsFromFile returned error: %v", err)
	}
	if summary.Failed != 0 {
		t.Fatalf("expected no failed definitions, got %d", summary.Failed)
	}
	if summary.DefinitionsCreated != 2 || summary.DefinitionsUpdated != 0 {
		t.Fatalf("expected 2 created definitions and 0 updated, got created=%d updated=%d", summary.DefinitionsCreated, summary.DefinitionsUpdated)
	}
	assertWorkflowSeedCounts(t, db)
	assertWorkflowSeedDependencies(t, db)
	assertWorkflowSeedControlRelationships(t, db)
	assertWorkflowSeedFilterControl(t, db)
	assertWorkflowSeedCronCadence(t, db)

	secondSummary, err := importWorkflowsFromFileForTest(context.Background(), db, sugar, "../../../../cmd/seed/testdata/soc2_workflows.sample.json")
	if err != nil {
		t.Fatalf("second importWorkflowsFromFile returned error: %v", err)
	}
	if secondSummary.Failed != 0 {
		t.Fatalf("expected no failed definitions on second import, got %d", secondSummary.Failed)
	}
	if secondSummary.DefinitionsCreated != 0 || secondSummary.DefinitionsUpdated != 2 {
		t.Fatalf("expected second import to update 2 definitions, got created=%d updated=%d", secondSummary.DefinitionsCreated, secondSummary.DefinitionsUpdated)
	}
	assertWorkflowSeedCounts(t, db)
	assertWorkflowSeedFilterControl(t, db)
}

func importWorkflowsFromFileForTest(ctx context.Context, db *gorm.DB, sugar *zap.SugaredLogger, path string) (SeedSummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return SeedSummary{}, fmt.Errorf("failed to open input file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && sugar != nil {
			sugar.Errorw("failed to close input file", "error", closeErr)
		}
	}()

	definitions, err := DecodeSeedDefinitions(f)
	if err != nil {
		return SeedSummary{}, fmt.Errorf("failed to decode input JSON: %w", err)
	}

	return ImportSeedDefinitions(ctx, db, sugar, definitions), nil
}

func TestDecodeSeedDefinitionsRejectsTrailingJSON(t *testing.T) {
	_, err := DecodeSeedDefinitions(strings.NewReader(`[{"key":"valid"}]{"extra":true}`))
	if err == nil {
		t.Fatal("expected trailing JSON error, got nil")
	}
	if !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected error to mention trailing content, got %q", err.Error())
	}
}

func TestImportWorkflowSeedDefinitionRejectsDuplicateStepNames(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	_, err := importSeedDefinition(db, SeedDefinition{
		Key:     "duplicate-step-name-test",
		Name:    "Duplicate Step Name Test",
		Version: "1.0.0",
		Steps: []SeedStep{
			{
				Name:            "Collect evidence",
				ResponsibleRole: "control-owner",
			},
			{
				Name:            "Collect evidence",
				ResponsibleRole: "control-owner",
			},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate step name error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate step name") {
		t.Fatalf("expected error to contain duplicate step name, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "Collect evidence") {
		t.Fatalf("expected error to contain duplicate step name value, got %q", err.Error())
	}
}

func TestImportWorkflowSeedDefinitionRejectsDuplicateInstanceNames(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)
	systemID := uuid.New().String()

	summary := ImportSeedDefinitions(context.Background(), db, nil, []SeedDefinition{
		{
			Key:     "duplicate-instance-name-test",
			Name:    "Duplicate Instance Name Test",
			Version: "1.0.0",
			Instances: []SeedInstance{
				{
					Name:     "Quarterly Review",
					SystemID: systemID,
					Cadence:  "monthly",
				},
				{
					Name:     "Quarterly Review",
					SystemID: systemID,
					Cadence:  "weekly",
				},
			},
		},
	})

	if summary.Failed != 1 {
		t.Fatalf("expected duplicate instance definition to fail once, got failed=%d summary=%+v", summary.Failed, summary)
	}
	if summary.Instances != 0 {
		t.Fatalf("expected no instances to import, got %d", summary.Instances)
	}

	var count int64
	if err := db.Model(&WorkflowInstance{}).Count(&count).Error; err != nil {
		t.Fatalf("failed to count workflow instances: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected duplicate instance import to roll back instances, got %d", count)
	}
}

func TestImportWorkflowSeedsTrimsKeyBeforeDeterministicIDs(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	firstSummary := ImportSeedDefinitions(context.Background(), db, nil, []SeedDefinition{
		{
			Key:         "  trim-key-test  ",
			Name:        "Trim Key Test",
			Description: "first import",
			Version:     "1.0.0",
		},
	})
	if firstSummary.Failed != 0 || firstSummary.DefinitionsCreated != 1 {
		t.Fatalf("expected first import to create one definition without failures, got created=%d failed=%d", firstSummary.DefinitionsCreated, firstSummary.Failed)
	}

	expectedID := deterministicSeedUUID("workflow-definition", "trim-key-test")
	var definition WorkflowDefinition
	if err := db.First(&definition, "id = ?", expectedID).Error; err != nil {
		t.Fatalf("expected workflow definition to use trimmed key ID: %v", err)
	}

	secondSummary := ImportSeedDefinitions(context.Background(), db, nil, []SeedDefinition{
		{
			Key:         "trim-key-test",
			Name:        "Trim Key Test",
			Description: "second import",
			Version:     "1.0.0",
		},
	})
	if secondSummary.Failed != 0 || secondSummary.DefinitionsUpdated != 1 {
		t.Fatalf("expected second import to update one definition without failures, got updated=%d failed=%d", secondSummary.DefinitionsUpdated, secondSummary.Failed)
	}

	var count int64
	if err := db.Model(&WorkflowDefinition{}).Count(&count).Error; err != nil {
		t.Fatalf("failed to count workflow definitions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected re-import with canonical key to keep one workflow definition, got %d", count)
	}
}

func TestImportWorkflowSeedStepGracePeriodDays(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	initialGracePeriod := 5
	updatedGracePeriod := 9
	seedDef := SeedDefinition{
		Key:     "step-grace-period-test",
		Name:    "Step Grace Period Test",
		Version: "1.0.0",
		Steps: []SeedStep{
			{
				Name:            "Review evidence",
				Order:           1,
				ResponsibleRole: "control-owner",
				GracePeriodDays: &initialGracePeriod,
			},
		},
	}
	if _, err := importSeedDefinition(db, seedDef); err != nil {
		t.Fatalf("importSeedDefinition returned error: %v", err)
	}

	stepID := deterministicSeedUUID("workflow-step-definition", seedDef.Key, "Review evidence")
	var step WorkflowStepDefinition
	if err := db.First(&step, "id = ?", stepID).Error; err != nil {
		t.Fatalf("failed to load workflow step definition: %v", err)
	}
	if step.GracePeriodDays == nil || *step.GracePeriodDays != initialGracePeriod {
		t.Fatalf("expected initial step grace period %d, got %v", initialGracePeriod, step.GracePeriodDays)
	}

	seedDef.Steps[0].GracePeriodDays = &updatedGracePeriod
	if _, err := importSeedDefinition(db, seedDef); err != nil {
		t.Fatalf("second importSeedDefinition returned error: %v", err)
	}
	if err := db.First(&step, "id = ?", stepID).Error; err != nil {
		t.Fatalf("failed to reload workflow step definition: %v", err)
	}
	if step.GracePeriodDays == nil || *step.GracePeriodDays != updatedGracePeriod {
		t.Fatalf("expected updated step grace period %d, got %v", updatedGracePeriod, step.GracePeriodDays)
	}
}

func TestImportWorkflowSeedPreservesSoftDeletedInstanceSchedule(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	seedKey := "soft-deleted-instance-schedule-test"
	instanceName := "Soft Deleted Instance"
	defID := deterministicSeedUUID("workflow-definition", seedKey)
	instanceID := deterministicSeedUUID("workflow-instance", seedKey, instanceName)
	systemID := uuid.New()
	deletedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	nextScheduledAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	lastExecutedAt := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)

	existingDefinition := WorkflowDefinition{
		UUIDModel: relational.UUIDModel{ID: &defID},
		Name:      "Soft Deleted Instance Schedule Test",
		Version:   "1.0.0",
	}
	if err := db.Create(&existingDefinition).Error; err != nil {
		t.Fatalf("failed to create existing workflow definition: %v", err)
	}

	existingInstance := WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &instanceID},
		DeletedAt:            gorm.DeletedAt{Time: deletedAt, Valid: true},
		Name:                 instanceName,
		Description:          "Original description",
		Cadence:              "monthly",
		IsActive:             true,
		NextScheduledAt:      &nextScheduledAt,
		LastExecutedAt:       &lastExecutedAt,
		WorkflowDefinitionID: &defID,
		SystemSecurityPlanID: &systemID,
	}
	if err := db.Create(&existingInstance).Error; err != nil {
		t.Fatalf("failed to create existing workflow instance: %v", err)
	}

	_, err := importSeedDefinition(db, SeedDefinition{
		Key:     seedKey,
		Name:    "Soft Deleted Instance Schedule Test",
		Version: "1.0.0",
		Instances: []SeedInstance{
			{
				Name:        instanceName,
				Description: "Updated description",
				SystemID:    systemID.String(),
				Cadence:     "weekly",
			},
		},
	})
	if err != nil {
		t.Fatalf("importSeedDefinition returned error: %v", err)
	}

	var updated WorkflowInstance
	if err := db.Unscoped().First(&updated, "id = ?", instanceID).Error; err != nil {
		t.Fatalf("failed to load workflow instance: %v", err)
	}
	if !updated.DeletedAt.Valid || !updated.DeletedAt.Time.Equal(deletedAt) {
		t.Fatalf("expected deleted_at to be preserved, got %+v", updated.DeletedAt)
	}
	if updated.NextScheduledAt == nil || !updated.NextScheduledAt.Equal(nextScheduledAt) {
		t.Fatalf("expected next_scheduled_at to be preserved, got %v", updated.NextScheduledAt)
	}
	if updated.LastExecutedAt == nil || !updated.LastExecutedAt.Equal(lastExecutedAt) {
		t.Fatalf("expected last_executed_at to be preserved, got %v", updated.LastExecutedAt)
	}
}

func TestUpsertWorkflowSeedPreservesWorkflowDefinitionAuditAndSoftDeleteFields(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	id := uuid.New()
	createdByID := uuid.New()
	updatedByID := uuid.New()
	createdAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	deletedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	originalGracePeriod := 3
	updatedGracePeriod := 7

	existing := WorkflowDefinition{
		UUIDModel:        relational.UUIDModel{ID: &id},
		CreatedAt:        createdAt,
		DeletedAt:        gorm.DeletedAt{Time: deletedAt, Valid: true},
		Name:             "Original name",
		Description:      "Original description",
		Version:          "1.0.0",
		SuggestedCadence: "monthly",
		EvidenceRequired: "original evidence",
		GracePeriodDays:  &originalGracePeriod,
		CreatedByID:      &createdByID,
		UpdatedByID:      &updatedByID,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("failed to create existing workflow definition: %v", err)
	}

	seed := WorkflowDefinition{
		UUIDModel:        relational.UUIDModel{ID: &id},
		Name:             "Updated name",
		Description:      "Updated description",
		Version:          "2.0.0",
		SuggestedCadence: "weekly",
		EvidenceRequired: "updated evidence",
		GracePeriodDays:  &updatedGracePeriod,
	}
	created, err := upsertSeed(db, &seed)
	if err != nil {
		t.Fatalf("upsertSeed returned error: %v", err)
	}
	if created {
		t.Fatal("expected soft-deleted workflow definition upsert to update an existing physical row")
	}

	var updated WorkflowDefinition
	if err := db.Unscoped().First(&updated, "id = ?", id).Error; err != nil {
		t.Fatalf("failed to load updated workflow definition: %v", err)
	}
	if updated.Name != "Updated name" ||
		updated.Description != "Updated description" ||
		updated.Version != "2.0.0" ||
		updated.SuggestedCadence != "weekly" ||
		updated.EvidenceRequired != "updated evidence" ||
		updated.GracePeriodDays == nil ||
		*updated.GracePeriodDays != updatedGracePeriod {
		t.Fatalf("expected workflow definition business fields to update, got %+v", updated)
	}
	if !updated.DeletedAt.Valid || !updated.DeletedAt.Time.Equal(deletedAt) {
		t.Fatalf("expected deleted_at to be preserved, got %+v", updated.DeletedAt)
	}
	if updated.CreatedByID == nil || *updated.CreatedByID != createdByID {
		t.Fatalf("expected created_by_id to be preserved, got %v", updated.CreatedByID)
	}
	if updated.UpdatedByID == nil || *updated.UpdatedByID != updatedByID {
		t.Fatalf("expected updated_by_id to be preserved, got %v", updated.UpdatedByID)
	}
	if !updated.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected created_at to be preserved, got %v", updated.CreatedAt)
	}
}

func TestUpsertWorkflowSeedPreservesWorkflowInstanceAuditAndSoftDeleteFields(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	id := uuid.New()
	definitionID := uuid.New()
	systemID := uuid.New()
	createdByID := uuid.New()
	updatedByID := uuid.New()
	createdAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	deletedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	lastExecutedAt := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)
	nextScheduledAt := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	originalGracePeriod := 3
	updatedGracePeriod := 7

	existing := WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &id},
		CreatedAt:            createdAt,
		DeletedAt:            gorm.DeletedAt{Time: deletedAt, Valid: true},
		Name:                 "Original name",
		Description:          "Original description",
		Cadence:              "monthly",
		IsActive:             false,
		GracePeriodDays:      &originalGracePeriod,
		NextScheduledAt:      &nextScheduledAt,
		LastExecutedAt:       &lastExecutedAt,
		CreatedByID:          &createdByID,
		UpdatedByID:          &updatedByID,
		WorkflowDefinitionID: &definitionID,
		SystemSecurityPlanID: &systemID,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("failed to create existing workflow instance: %v", err)
	}

	seed := WorkflowInstance{
		UUIDModel:            relational.UUIDModel{ID: &id},
		Name:                 "Updated name",
		Description:          "Updated description",
		Cadence:              "weekly",
		IsActive:             true,
		GracePeriodDays:      &updatedGracePeriod,
		NextScheduledAt:      &nextScheduledAt,
		LastExecutedAt:       &lastExecutedAt,
		WorkflowDefinitionID: &definitionID,
		SystemSecurityPlanID: &systemID,
	}
	created, err := upsertSeed(db, &seed)
	if err != nil {
		t.Fatalf("upsertSeed returned error: %v", err)
	}
	if created {
		t.Fatal("expected soft-deleted workflow instance upsert to update an existing physical row")
	}

	var updated WorkflowInstance
	if err := db.Unscoped().First(&updated, "id = ?", id).Error; err != nil {
		t.Fatalf("failed to load updated workflow instance: %v", err)
	}
	if updated.Name != "Updated name" ||
		updated.Description != "Updated description" ||
		updated.Cadence != "weekly" ||
		!updated.IsActive ||
		updated.GracePeriodDays == nil ||
		*updated.GracePeriodDays != updatedGracePeriod ||
		updated.NextScheduledAt == nil ||
		!updated.NextScheduledAt.Equal(nextScheduledAt) ||
		updated.LastExecutedAt == nil ||
		!updated.LastExecutedAt.Equal(lastExecutedAt) {
		t.Fatalf("expected workflow instance business fields to update, got %+v", updated)
	}
	if !updated.DeletedAt.Valid || !updated.DeletedAt.Time.Equal(deletedAt) {
		t.Fatalf("expected deleted_at to be preserved, got %+v", updated.DeletedAt)
	}
	if updated.CreatedByID == nil || *updated.CreatedByID != createdByID {
		t.Fatalf("expected created_by_id to be preserved, got %v", updated.CreatedByID)
	}
	if updated.UpdatedByID == nil || *updated.UpdatedByID != updatedByID {
		t.Fatalf("expected updated_by_id to be preserved, got %v", updated.UpdatedByID)
	}
	if !updated.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected created_at to be preserved, got %v", updated.CreatedAt)
	}
}

func assertWorkflowSeedCounts(t *testing.T, db *gorm.DB) {
	t.Helper()

	counts := []struct {
		name     string
		model    interface{}
		expected int64
	}{
		{"workflow definitions", &WorkflowDefinition{}, 2},
		{"workflow steps", &WorkflowStepDefinition{}, 10},
		{"step dependencies", &StepDependency{}, 8},
		{"control relationships", &ControlRelationship{}, 6},
		{"workflow instances", &WorkflowInstance{}, 2},
		{"role assignments", &RoleAssignment{}, 2},
	}

	for _, tc := range counts {
		var count int64
		if err := db.Model(tc.model).Count(&count).Error; err != nil {
			t.Fatalf("failed to count %s: %v", tc.name, err)
		}
		if count != tc.expected {
			t.Fatalf("expected %d %s, got %d", tc.expected, tc.name, count)
		}
	}
}

func assertWorkflowSeedDependencies(t *testing.T, db *gorm.DB) {
	t.Helper()

	var step WorkflowStepDefinition
	if err := db.Preload("DependsOn.DependsOnStep").
		Where("name = ?", "Document deprovisioning requirements").
		First(&step).Error; err != nil {
		t.Fatalf("failed to load dependent step: %v", err)
	}
	if len(step.DependsOn) != 1 {
		t.Fatalf("expected 1 dependency for %q, got %d", step.Name, len(step.DependsOn))
	}
	if step.DependsOn[0].DependsOnStep == nil {
		t.Fatalf("expected dependency to resolve to a workflow step")
	}
	if step.DependsOn[0].DependsOnStep.Name != "Define control scope & objectives" {
		t.Fatalf("expected dependency to resolve by name, got %q", step.DependsOn[0].DependsOnStep.Name)
	}
}

func assertWorkflowSeedControlRelationships(t *testing.T, db *gorm.DB) {
	t.Helper()

	var relationship ControlRelationship
	if err := db.Where("control_id = ?", "ctrl-cc5-2-002").First(&relationship).Error; err != nil {
		t.Fatalf("failed to load control relationship: %v", err)
	}
	if relationship.CatalogID != "0f9d8e10-363b-4a8f-ade5-f11c0b2b1202" {
		t.Fatalf("expected catalog id to pass through, got %q", relationship.CatalogID)
	}
	if relationship.ControlSource != "0f9d8e10-363b-4a8f-ade5-f11c0b2b1202" {
		t.Fatalf("expected control source to use catalog id, got %q", relationship.ControlSource)
	}
}

func seedWorkflowFilterControl(t *testing.T, db *gorm.DB) {
	t.Helper()

	catalogID := uuid.MustParse("0f9d8e10-363b-4a8f-ade5-f11c0b2b1202")
	control := relational.Control{
		CatalogID: catalogID,
		ID:        "ctrl-cc5-2-002",
		Title:     "Technology control scope is defined",
	}
	if err := db.Create(&control).Error; err != nil {
		t.Fatalf("failed to seed workflow filter control: %v", err)
	}
}

func assertWorkflowSeedFilterControl(t *testing.T, db *gorm.DB) {
	t.Helper()

	var filters []relational.Filter
	if err := db.Preload("Controls").
		Where("name = ?", "Workflow: Technology Controls Governance & Independent Review").
		Find(&filters).Error; err != nil {
		t.Fatalf("failed to load workflow filter: %v", err)
	}
	if len(filters) != 1 {
		t.Fatalf("expected one deterministic workflow filter, got %d", len(filters))
	}

	if len(filters[0].Controls) != 1 {
		t.Fatalf("expected workflow filter to have one resolved control, got %d", len(filters[0].Controls))
	}
	control := filters[0].Controls[0]
	if control.CatalogID != uuid.MustParse("0f9d8e10-363b-4a8f-ade5-f11c0b2b1202") || control.ID != "ctrl-cc5-2-002" {
		t.Fatalf("expected workflow filter control ctrl-cc5-2-002 in SOC 2 catalog, got catalog=%s control=%s", control.CatalogID, control.ID)
	}

	var joinCount int64
	if err := db.Table("filter_controls").Count(&joinCount).Error; err != nil {
		t.Fatalf("failed to count filter controls: %v", err)
	}
	if joinCount != 1 {
		t.Fatalf("expected repeated import to keep one filter control association, got %d", joinCount)
	}
}

func assertWorkflowSeedCronCadence(t *testing.T, db *gorm.DB) {
	t.Helper()

	var definition WorkflowDefinition
	if err := db.Where("name = ?", "Asset Disposal, Media Sanitization & Handling").First(&definition).Error; err != nil {
		t.Fatalf("failed to load cron workflow definition: %v", err)
	}
	if definition.SuggestedCadence != "cron:0 0 9 1 1,7 *" {
		t.Fatalf("expected cron cadence to be stored, got %q", definition.SuggestedCadence)
	}

	var instance WorkflowInstance
	if err := db.Where("name = ?", "Asset Disposal, Media Sanitization & Handling — ToDo Demo App").First(&instance).Error; err != nil {
		t.Fatalf("failed to load cron workflow instance: %v", err)
	}
	if instance.Cadence != "cron:0 0 9 1 1,7 *" {
		t.Fatalf("expected cron instance cadence to be stored, got %q", instance.Cadence)
	}
}
