package workflows

// This file imports all workflow-related entities for easy inclusion in migrations
// and provides a centralized location for workflow database models

// All Workflow Entities:
// - WorkflowDefinition: Template for recurring compliance activities
// - WorkflowStepDefinition: Individual steps with dependencies
// - StepDependency: DAG relationships between steps
// - StepTrigger: Automatic step transition conditions (Phase 5)
// - WorkflowInstance: Specific implementation of a workflow
// - RoleAssignment: Role assignments for workflow instances
// - WorkflowExecution: Specific run of a workflow instance
// - StepExecution: Execution of a step within a workflow execution
// - StepEvidence: Evidence submitted for step executions
// - ControlRelationship: Mapping between workflows and compliance controls

// GetWorkflowEntities returns all workflow entities for migration purposes
func GetWorkflowEntities() []interface{} {
	return []interface{}{
		&WorkflowDefinition{},
		&WorkflowStepDefinition{},
		&StepDependency{},
		&StepTrigger{},
		&WorkflowInstance{},
		&RoleAssignment{},
		&WorkflowExecution{},
		&StepExecution{},
		&StepEvidence{},
		&StepReassignmentHistory{},
		&ControlRelationship{},
	}
}

// GetWorkflowTables returns all workflow table names for migration purposes
func GetWorkflowTables() []string {
	return []string{
		"workflow_definitions",
		"workflow_step_definitions",
		"step_dependencies",
		"step_triggers",
		"workflow_instances",
		"role_assignments",
		"workflow_executions",
		"step_executions",
		"step_evidence",
		"step_reassignment_history",
		"control_relationships",
	}
}
