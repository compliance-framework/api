package workflow

import (
	"fmt"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
)

// stepIndex provides O(1) lookup for steps by ID
type stepIndex map[string]*workflows.WorkflowStepDefinition

// buildStepIndex creates an index for fast step lookups
func buildStepIndex(steps []workflows.WorkflowStepDefinition) stepIndex {
	index := make(stepIndex, len(steps))
	for i := range steps {
		index[steps[i].ID.String()] = &steps[i]
	}
	return index
}

// findStep retrieves a step by ID from the index
func (idx stepIndex) findStep(id *uuid.UUID) (*workflows.WorkflowStepDefinition, error) {
	step, exists := idx[id.String()]
	if !exists {
		return nil, fmt.Errorf("step with id %s not found", id.String())
	}
	return step, nil
}

// validateStepsNotEmpty checks if steps slice is empty
func validateStepsNotEmpty(steps []workflows.WorkflowStepDefinition) error {
	if len(steps) == 0 {
		return fmt.Errorf("workflow has no steps defined")
	}
	return nil
}
