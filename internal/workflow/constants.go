package workflow

import "time"

// Execution timing constants
const (
	DefaultExecutionTimeout = 30 * time.Second
	StepPollInterval        = 100 * time.Millisecond
	StepSimulationTime      = 100 * time.Millisecond
)

// Orphan step reasons
const (
	OrphanReasonNoDependencies = "no_dependencies"
	OrphanReasonNoDependents   = "no_dependents"
)

// StepStatus represents the status of a workflow step execution
// Note: This type mirrors workflows.StepExecutionStatus for use in the workflow orchestration layer.
// Both types must be kept in sync. The string values are identical to ensure compatibility.
type StepStatus string

// Status constants for workflow step executions
// These values match workflows.StepExecutionStatus constants
const (
	StatusPending    StepStatus = "pending"
	StatusBlocked    StepStatus = "blocked"
	StatusInProgress StepStatus = "in_progress"
	StatusCompleted  StepStatus = "completed"
	StatusFailed     StepStatus = "failed"
	StatusSkipped    StepStatus = "skipped"
	StatusCancelled  StepStatus = "cancelled"
)

// IsValid checks if the step status is valid
func (s StepStatus) IsValid() bool {
	switch s {
	case StatusPending, StatusBlocked, StatusInProgress, StatusCompleted, StatusFailed, StatusSkipped, StatusCancelled:
		return true
	}
	return false
}

// String returns the string representation of the status
func (s StepStatus) String() string {
	return string(s)
}
