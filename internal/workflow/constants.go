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

// Status constants
const (
	StatusPending    = "pending"
	StatusInProgress = "in_progress"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
	StatusCancelled  = "cancelled"
	StatusBlocked    = "blocked"
)
