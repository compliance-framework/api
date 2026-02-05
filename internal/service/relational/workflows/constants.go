package workflows

// Field length constraints
const (
	MaxNameLength          = 255
	MaxDescriptionLength   = 1000
	MaxRoleNameLength      = 255
	MaxControlIDLength     = 255
	MaxControlSourceLength = 255
	MaxAssignedToIDLength  = 255
)

// CadenceType represents a workflow scheduling cadence
type CadenceType string

// CronPrefix is the prefix for custom cron expressions
const CronPrefix = "cron:"

// Valid cadence values for workflow scheduling
const (
	CadenceDaily     CadenceType = "daily"
	CadenceWeekly    CadenceType = "weekly"
	CadenceMonthly   CadenceType = "monthly"
	CadenceQuarterly CadenceType = "quarterly"
	CadenceAnnually  CadenceType = "annually"
)

// IsValid checks if the cadence type is valid
func (c CadenceType) IsValid() bool {
	switch c {
	case CadenceDaily, CadenceWeekly, CadenceMonthly, CadenceQuarterly, CadenceAnnually:
		return true
	}
	// Check if it's a custom cron expression
	if c.IsCron() {
		return true
	}
	return false
}

// IsCron checks if the cadence is a custom cron expression
func (c CadenceType) IsCron() bool {
	return len(c) > len(CronPrefix) && string(c)[:len(CronPrefix)] == CronPrefix
}

// CronExpression extracts the cron expression from a cron cadence
// Returns empty string if not a cron cadence
func (c CadenceType) CronExpression() string {
	if !c.IsCron() {
		return ""
	}
	return string(c)[len(CronPrefix):]
}

// String returns the string representation
func (c CadenceType) String() string {
	return string(c)
}

// AssignmentType represents the type of assignment for role assignments and step executions
type AssignmentType string

// Valid assignment types
const (
	AssignmentTypeUser  AssignmentType = "user"
	AssignmentTypeGroup AssignmentType = "group"
	AssignmentTypeEmail AssignmentType = "email"
)

// IsValid checks if the assignment type is valid
func (a AssignmentType) IsValid() bool {
	switch a {
	case AssignmentTypeUser, AssignmentTypeGroup, AssignmentTypeEmail:
		return true
	}
	return false
}

// String returns the string representation
func (a AssignmentType) String() string {
	return string(a)
}

// WorkflowExecutionStatus represents the status of a workflow execution
type WorkflowExecutionStatus string

// Valid workflow execution statuses
const (
	WorkflowStatusPending    WorkflowExecutionStatus = "pending"
	WorkflowStatusInProgress WorkflowExecutionStatus = "in_progress"
	WorkflowStatusCompleted  WorkflowExecutionStatus = "completed"
	WorkflowStatusFailed     WorkflowExecutionStatus = "failed"
	WorkflowStatusCancelled  WorkflowExecutionStatus = "cancelled"
)

// IsValid checks if the workflow execution status is valid
func (w WorkflowExecutionStatus) IsValid() bool {
	switch w {
	case WorkflowStatusPending, WorkflowStatusInProgress, WorkflowStatusCompleted, WorkflowStatusFailed, WorkflowStatusCancelled:
		return true
	}
	return false
}

// String returns the string representation
func (w WorkflowExecutionStatus) String() string {
	return string(w)
}

// StepExecutionStatus represents the status of a step execution
// Note: This type is mirrored by workflow.StepStatus in the orchestration layer.
// Both types must be kept in sync. The string values are identical to ensure compatibility.
type StepExecutionStatus string

// Valid step execution statuses
// These values match workflow.StepStatus constants
const (
	StepStatusPending    StepExecutionStatus = "pending"
	StepStatusBlocked    StepExecutionStatus = "blocked"
	StepStatusInProgress StepExecutionStatus = "in_progress"
	StepStatusCompleted  StepExecutionStatus = "completed"
	StepStatusFailed     StepExecutionStatus = "failed"
	StepStatusSkipped    StepExecutionStatus = "skipped"
)

// IsValid checks if the step execution status is valid
func (s StepExecutionStatus) IsValid() bool {
	switch s {
	case StepStatusPending, StepStatusBlocked, StepStatusInProgress, StepStatusCompleted, StepStatusFailed, StepStatusSkipped:
		return true
	}
	return false
}

// String returns the string representation
func (s StepExecutionStatus) String() string {
	return string(s)
}

// TriggerType represents the type of trigger for workflow execution
type TriggerType string

// Valid trigger types
const (
	TriggerManual    TriggerType = "manual"
	TriggerScheduled TriggerType = "scheduled"
	TriggerAutomatic TriggerType = "automatic"
)

// IsValid checks if the trigger type is valid
func (t TriggerType) IsValid() bool {
	switch t {
	case TriggerManual, TriggerScheduled, TriggerAutomatic:
		return true
	}
	return false
}

// String returns the string representation
func (t TriggerType) String() string {
	return string(t)
}

// RelationshipType represents the type of control relationship
type RelationshipType string

// Valid control relationship types
const (
	RelationshipSatisfies          RelationshipType = "satisfies"
	RelationshipPartiallySatisfies RelationshipType = "partially_satisfies"
	RelationshipSupports           RelationshipType = "supports"
)

// IsValid checks if the relationship type is valid
func (r RelationshipType) IsValid() bool {
	switch r {
	case RelationshipSatisfies, RelationshipPartiallySatisfies, RelationshipSupports:
		return true
	}
	return false
}

// String returns the string representation
func (r RelationshipType) String() string {
	return string(r)
}

// RelationshipStrength represents the strength of a control relationship
type RelationshipStrength string

// Valid control relationship strengths
const (
	StrengthPrimary    RelationshipStrength = "primary"
	StrengthSecondary  RelationshipStrength = "secondary"
	StrengthSupporting RelationshipStrength = "supporting"
)

// IsValid checks if the relationship strength is valid
func (r RelationshipStrength) IsValid() bool {
	switch r {
	case StrengthPrimary, StrengthSecondary, StrengthSupporting:
		return true
	}
	return false
}

// String returns the string representation
func (r RelationshipStrength) String() string {
	return string(r)
}
