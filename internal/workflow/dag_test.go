package workflow

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateStepsNotEmpty(t *testing.T) {
	// Test empty steps
	err := validateStepsNotEmpty([]workflows.WorkflowStepDefinition{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no steps defined")

	// Test non-empty steps
	stepA := workflows.WorkflowStepDefinition{Name: "Step A"}
	err = validateStepsNotEmpty([]workflows.WorkflowStepDefinition{stepA})
	require.NoError(t, err)
}

func TestBuildStepIndex(t *testing.T) {
	stepA := workflows.WorkflowStepDefinition{Name: "Step A"}
	stepB := workflows.WorkflowStepDefinition{Name: "Step B"}

	// Set the UUID IDs
	idA := uuid.New()
	idB := uuid.New()
	stepA.ID = &idA
	stepB.ID = &idB

	steps := []workflows.WorkflowStepDefinition{stepA, stepB}

	index := buildStepIndex(steps)

	// Test finding existing steps
	foundStep, err := index.findStep(stepA.ID)
	require.NoError(t, err)
	assert.Equal(t, stepA.Name, foundStep.Name)

	foundStep, err = index.findStep(stepB.ID)
	require.NoError(t, err)
	assert.Equal(t, stepB.Name, foundStep.Name)

	// Test finding non-existent step
	nonExistentID := uuid.New()
	_, err = index.findStep(&nonExistentID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCountDependents(t *testing.T) {
	stepA := workflows.WorkflowStepDefinition{Name: "Step A"}
	stepB := workflows.WorkflowStepDefinition{Name: "Step B"}
	stepC := workflows.WorkflowStepDefinition{Name: "Step C"}

	// Set the UUID IDs
	idA := uuid.New()
	idB := uuid.New()
	idC := uuid.New()
	stepA.ID = &idA
	stepB.ID = &idB
	stepC.ID = &idC

	steps := []workflows.WorkflowStepDefinition{stepA, stepB, stepC}

	// Create dependency map: A depends on B, B depends on C
	depMap := map[string][]workflows.WorkflowStepDefinition{
		stepA.ID.String(): {stepB},
		stepB.ID.String(): {stepC},
		stepC.ID.String(): {},
	}

	dependents := countDependents(steps, depMap)

	// C has 1 dependent (B)
	assert.Equal(t, 1, dependents[stepC.ID.String()])
	// B has 1 dependent (A)
	assert.Equal(t, 1, dependents[stepB.ID.String()])
	// A has 0 dependents
	assert.Equal(t, 0, dependents[stepA.ID.String()])
}

func TestDAGValidationResult_Structure(t *testing.T) {
	result := &DAGValidationResult{
		IsValid:       false,
		Errors:        []string{"test error"},
		Warnings:      []string{"test warning"},
		Cycles:        []DAGCycle{{Path: "A -> B -> A"}},
		OrphanedSteps: []OrphanedStep{{StepName: "Orphaned Step"}},
		Dependencies:  []DependencyIssue{{Issue: "dependency issue"}},
	}

	assert.False(t, result.IsValid)
	assert.Len(t, result.Errors, 1)
	assert.Len(t, result.Warnings, 1)
	assert.Len(t, result.Cycles, 1)
	assert.Len(t, result.OrphanedSteps, 1)
	assert.Len(t, result.Dependencies, 1)
}

func TestDAGCycle_Structure(t *testing.T) {
	cycle := DAGCycle{
		Steps: []string{"A", "B", "C"},
		Path:  "A -> B -> C -> A",
	}

	assert.Len(t, cycle.Steps, 3)
	assert.Equal(t, "A -> B -> C -> A", cycle.Path)
}

func TestOrphanedStep_Structure(t *testing.T) {
	stepID := uuid.New()
	orphaned := OrphanedStep{
		StepID:   stepID,
		StepName: "Orphaned Step",
		Reason:   "no_dependencies",
	}

	assert.Equal(t, stepID, orphaned.StepID)
	assert.Equal(t, "Orphaned Step", orphaned.StepName)
	assert.Equal(t, "no_dependencies", orphaned.Reason)
}

func TestDependencyIssue_Structure(t *testing.T) {
	fromID := uuid.New()
	toID := uuid.New()

	issue := DependencyIssue{
		FromStepID:   fromID,
		FromStepName: "Step A",
		ToStepID:     toID,
		ToStepName:   "Step B",
		Issue:        "test issue",
	}

	assert.Equal(t, fromID, issue.FromStepID)
	assert.Equal(t, "Step A", issue.FromStepName)
	assert.Equal(t, toID, issue.ToStepID)
	assert.Equal(t, "Step B", issue.ToStepName)
	assert.Equal(t, "test issue", issue.Issue)
}

// Benchmark test for performance validation
func BenchmarkDAGValidation_ComplexWorkflow(b *testing.B) {
	// Create a complex workflow with many steps and dependencies
	steps := make([]workflows.WorkflowStepDefinition, 100)
	for i := 0; i < 100; i++ {
		steps[i] = workflows.WorkflowStepDefinition{Name: "Step " + string(rune(i))}
	}

	// Create dependency map
	depMap := make(map[string][]workflows.WorkflowStepDefinition)
	for i := 1; i < 100; i++ {
		depMap[steps[i].ID.String()] = []workflows.WorkflowStepDefinition{steps[i-1]}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dependents := countDependents(steps, depMap)
		if len(dependents) != 100 {
			b.Fatal("Unexpected dependents count")
		}
	}
}
