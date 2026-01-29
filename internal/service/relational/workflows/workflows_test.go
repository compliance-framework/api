package workflows

import (
	"testing"
)

// TestWorkflowEntities tests that all workflow entities can be instantiated
func TestWorkflowEntities(t *testing.T) {
	entities := GetWorkflowEntities()

	// Verify we have the expected number of entities
	expectedCount := 10
	if len(entities) != expectedCount {
		t.Errorf("Expected %d entities, got %d", expectedCount, len(entities))
	}

	// Test that each entity can be instantiated
	for _, entity := range entities {
		switch v := entity.(type) {
		case *WorkflowDefinition:
			v.Name = "Test Workflow"
			v.Description = "Test Description"
		case *WorkflowStepDefinition:
			v.Name = "Test Step"
			v.ResponsibleRole = "test_role"
		case *StepDependency:
			// Just test instantiation
		case *StepTrigger:
			v.TriggerType = "test"
		case *WorkflowInstance:
			v.Name = "Test Instance"
			v.SystemName = "Test System"
		case *RoleAssignment:
			v.RoleName = "test_role"
			v.AssignedToType = "user"
		case *WorkflowExecution:
			v.Status = "pending"
		case *StepExecution:
			v.Status = "pending"
		case *StepEvidence:
			v.Name = "Test Evidence"
			v.EvidenceType = "document"
		case *ControlRelationship:
			v.ControlID = "AC-1"
			v.ControlSource = "NIST 800-53"
		default:
			t.Errorf("Unknown entity type: %T", v)
		}
	}
}

// TestWorkflowTables tests that all workflow table names are defined
func TestWorkflowTables(t *testing.T) {
	tables := GetWorkflowTables()

	expectedTables := []string{
		"workflow_definitions",
		"workflow_step_definitions",
		"step_dependencies",
		"step_triggers",
		"workflow_instances",
		"role_assignments",
		"workflow_executions",
		"step_executions",
		"step_evidence",
		"control_relationships",
	}

	if len(tables) != len(expectedTables) {
		t.Errorf("Expected %d tables, got %d", len(expectedTables), len(tables))
	}

	for i, expected := range expectedTables {
		if i >= len(tables) || tables[i] != expected {
			t.Errorf("Expected table %s at index %d, got %s", expected, i, tables[i])
		}
	}
}

// TestGORMTags tests that entities have proper GORM tags
func TestGORMTags(t *testing.T) {
	// Test WorkflowDefinition
	wd := &WorkflowDefinition{}
	if wd.TableName() != "workflow_definitions" {
		t.Errorf("Expected table name workflow_definitions, got %s", wd.TableName())
	}

	// Test WorkflowStepDefinition
	wsd := &WorkflowStepDefinition{}
	if wsd.TableName() != "workflow_step_definitions" {
		t.Errorf("Expected table name workflow_step_definitions, got %s", wsd.TableName())
	}

	// Test WorkflowInstance
	wi := &WorkflowInstance{}
	if wi.TableName() != "workflow_instances" {
		t.Errorf("Expected table name workflow_instances, got %s", wi.TableName())
	}

	// Test WorkflowExecution
	we := &WorkflowExecution{}
	if we.TableName() != "workflow_executions" {
		t.Errorf("Expected table name workflow_executions, got %s", we.TableName())
	}

	// Test StepExecution
	se := &StepExecution{}
	if se.TableName() != "step_executions" {
		t.Errorf("Expected table name step_executions, got %s", se.TableName())
	}
}
