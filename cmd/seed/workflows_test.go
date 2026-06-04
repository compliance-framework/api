package seed

import (
	"context"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"go.uber.org/zap"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestImportWorkflowsFromFileUsesSharedImporter(t *testing.T) {
	db := setupWorkflowSeedCommandTestDB(t)

	summary, err := importWorkflowsFromFile(context.Background(), db, zap.NewNop().Sugar(), "testdata/soc2_workflows.sample.json")
	if err != nil {
		t.Fatalf("importWorkflowsFromFile returned error: %v", err)
	}
	if summary.Failed != 0 {
		t.Fatalf("expected no failed definitions, got %d", summary.Failed)
	}
	if summary.DefinitionsCreated != 2 || summary.DefinitionsUpdated != 0 {
		t.Fatalf("expected 2 created definitions and 0 updated, got created=%d updated=%d", summary.DefinitionsCreated, summary.DefinitionsUpdated)
	}
}

func setupWorkflowSeedCommandTestDB(t *testing.T) *gorm.DB {
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
	if err := db.AutoMigrate(&relational.Control{}, &relational.Filter{}); err != nil {
		t.Fatalf("failed to migrate filter entities: %v", err)
	}

	return db
}
