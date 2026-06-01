package seed

import (
	"context"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
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

	for _, entity := range workflows.GetWorkflowEntities() {
		if err := db.AutoMigrate(entity); err != nil {
			t.Fatalf("failed to migrate %T: %v", entity, err)
		}
	}

	return db
}

func TestImportWorkflowsFromFile(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)
	sugar := zap.NewNop().Sugar()

	summary, err := importWorkflowsFromFile(context.Background(), db, sugar, "testdata/soc2_workflows.sample.json")
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
	assertWorkflowSeedCronCadence(t, db)

	secondSummary, err := importWorkflowsFromFile(context.Background(), db, sugar, "testdata/soc2_workflows.sample.json")
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
}

func TestImportWorkflowSeedDefinitionRejectsDuplicateStepNames(t *testing.T) {
	db := setupWorkflowSeedTestDB(t)

	_, err := importWorkflowSeedDefinition(db, workflowSeedDefinition{
		Key:     "duplicate-step-name-test",
		Name:    "Duplicate Step Name Test",
		Version: "1.0.0",
		Steps: []workflowSeedStep{
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

func assertWorkflowSeedCounts(t *testing.T, db *gorm.DB) {
	t.Helper()

	counts := []struct {
		name     string
		model    interface{}
		expected int64
	}{
		{"workflow definitions", &workflows.WorkflowDefinition{}, 2},
		{"workflow steps", &workflows.WorkflowStepDefinition{}, 10},
		{"step dependencies", &workflows.StepDependency{}, 8},
		{"control relationships", &workflows.ControlRelationship{}, 6},
		{"workflow instances", &workflows.WorkflowInstance{}, 2},
		{"role assignments", &workflows.RoleAssignment{}, 2},
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

	var step workflows.WorkflowStepDefinition
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

	var relationship workflows.ControlRelationship
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

func assertWorkflowSeedCronCadence(t *testing.T, db *gorm.DB) {
	t.Helper()

	var definition workflows.WorkflowDefinition
	if err := db.Where("name = ?", "Asset Disposal, Media Sanitization & Handling").First(&definition).Error; err != nil {
		t.Fatalf("failed to load cron workflow definition: %v", err)
	}
	if definition.SuggestedCadence != "cron:0 0 9 1 1,7 *" {
		t.Fatalf("expected cron cadence to be stored, got %q", definition.SuggestedCadence)
	}

	var instance workflows.WorkflowInstance
	if err := db.Where("name = ?", "Asset Disposal, Media Sanitization & Handling — ToDo Demo App").First(&instance).Error; err != nil {
		t.Fatalf("failed to load cron workflow instance: %v", err)
	}
	if instance.Cadence != "cron:0 0 9 1 1,7 *" {
		t.Fatalf("expected cron instance cadence to be stored, got %q", instance.Cadence)
	}
}
