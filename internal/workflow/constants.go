package workflow

import "github.com/compliance-framework/api/internal/service/relational/workflows"

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
	StatusOverdue    StepStatus = "overdue"
	StatusCompleted  StepStatus = "completed"
	StatusFailed     StepStatus = "failed"
	StatusSkipped    StepStatus = "skipped"
	StatusCancelled  StepStatus = "cancelled"
)

// IsValid checks if the step status is valid
func (s StepStatus) IsValid() bool {
	switch s {
	case StatusPending, StatusBlocked, StatusInProgress, StatusOverdue, StatusCompleted, StatusFailed, StatusSkipped, StatusCancelled:
		return true
	}
	return false
}

// String returns the string representation of the status
func (s StepStatus) String() string {
	return string(s)
}

// StepStatusCounts holds a count of step executions per status.
type StepStatusCounts struct {
	Pending    int
	Blocked    int
	InProgress int
	Overdue    int
	Completed  int
	Failed     int
	Skipped    int
	Cancelled  int
}

// Total returns the sum of all status counts.
func (c StepStatusCounts) Total() int {
	return c.Pending + c.Blocked + c.InProgress + c.Overdue +
		c.Completed + c.Failed + c.Skipped + c.Cancelled
}

// AllTerminal returns true when no step can make further progress, matching the semantics
// of checkWorkflowCompletion: all steps must be in {completed, failed, skipped} — cancelled
// steps are intentionally not treated as terminal here so that a partially-cancelled execution
// is not incorrectly marked complete.
func (c StepStatusCounts) AllTerminal() bool {
	return c.Pending == 0 && c.Blocked == 0 && c.InProgress == 0 && c.Overdue == 0 && c.Cancelled == 0
}

// CountStepStatuses counts step executions by status.
func CountStepStatuses(steps []workflows.StepExecution) StepStatusCounts {
	var c StepStatusCounts
	for _, s := range steps {
		switch s.Status {
		case StatusPending.String():
			c.Pending++
		case StatusBlocked.String():
			c.Blocked++
		case StatusInProgress.String():
			c.InProgress++
		case StatusOverdue.String():
			c.Overdue++
		case StatusCompleted.String():
			c.Completed++
		case StatusFailed.String():
			c.Failed++
		case StatusSkipped.String():
			c.Skipped++
		case StatusCancelled.String():
			c.Cancelled++
		}
	}
	return c
}
