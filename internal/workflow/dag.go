package workflow

import (
	"github.com/google/uuid"
)

// DAGValidationResult contains the results of DAG validation
type DAGValidationResult struct {
	IsValid       bool
	Errors        []string
	Warnings      []string
	Cycles        []DAGCycle
	OrphanedSteps []OrphanedStep
	Dependencies  []DependencyIssue
}

// DAGCycle represents a detected cycle in the DAG
type DAGCycle struct {
	Steps []string // Step names/IDs in cycle order
	Path  string   // Human-readable cycle path
}

// OrphanedStep represents a step with no dependencies or dependents
type OrphanedStep struct {
	StepID   uuid.UUID
	StepName string
	Reason   string // "no_dependencies" or "no_dependents"
}

// DependencyIssue represents a dependency validation problem
type DependencyIssue struct {
	FromStepID   uuid.UUID
	FromStepName string
	ToStepID     uuid.UUID
	ToStepName   string
	Issue        string
}
