//go:build integration

package workflows

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&workflows.WorkflowDefinition{},
		&workflows.WorkflowStepDefinition{},
		&workflows.StepDependency{},
		&workflows.StepTrigger{},
		&workflows.ControlRelationship{},
		&workflows.WorkflowInstance{},
		&workflows.RoleAssignment{},
		&workflows.WorkflowExecution{},
		&workflows.StepExecution{},
		&workflows.StepEvidence{},
	)
	require.NoError(t, err)

	return db
}
