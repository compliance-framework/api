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
type StepStatus string

// Status constants for workflow step executions
const (
	StatusPending    StepStatus = "pending"
	StatusInProgress StepStatus = "in_progress"
	StatusCompleted  StepStatus = "completed"
	StatusFailed     StepStatus = "failed"
	StatusCancelled  StepStatus = "cancelled"
	StatusBlocked    StepStatus = "blocked"
)

// IsValid checks if the step status is valid
func (s StepStatus) IsValid() bool {
	switch s {
	case StatusPending, StatusInProgress, StatusCompleted, StatusFailed, StatusCancelled, StatusBlocked:
		return true
	}
	return false
}

// String returns the string representation of the status
func (s StepStatus) String() string {
	return string(s)
}
