package workflow

import (
	"errors"
	"fmt"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/google/uuid"
)

// DAGValidator provides comprehensive DAG validation functionality
type DAGValidator struct {
	stepService *workflows.WorkflowStepDefinitionService
}

// NewDAGValidator creates a new DAG validator
func NewDAGValidator(stepService *workflows.WorkflowStepDefinitionService) *DAGValidator {
	return &DAGValidator{
		stepService: stepService,
	}
}

// ValidateDAG performs comprehensive validation of a workflow DAG
func (dv *DAGValidator) ValidateDAG(workflowDefID *uuid.UUID) (*DAGValidationResult, error) {
	result := &DAGValidationResult{
		IsValid:  true,
		Errors:   []string{},
		Warnings: []string{},
	}

	// Get all steps in the workflow
	steps, err := dv.stepService.GetByWorkflowDefinitionID(workflowDefID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve workflow steps: %w", err)
	}

	if err := validateStepsNotEmpty(steps); err != nil {
		result.IsValid = false
		result.Errors = append(result.Errors, err.Error())
		return result, nil
	}

	// Build dependency map once for efficiency
	depMap, err := dv.getDependencyMap(steps)
	if err != nil {
		return nil, err
	}

	// 1. Check for cycles
	if err := dv.checkCycles(steps, depMap, result); err != nil {
		return nil, err
	}

	// 2. Check for orphaned steps
	if err := dv.checkOrphanedSteps(steps, depMap, result); err != nil {
		return nil, err
	}

	// 3. Validate dependencies
	if err := dv.checkDependencyIssues(steps, depMap, result); err != nil {
		return nil, err
	}

	return result, nil
}

// getDependencyMap builds a dependency map for efficient lookups
func (dv *DAGValidator) getDependencyMap(steps []workflows.WorkflowStepDefinition) (map[string][]workflows.WorkflowStepDefinition, error) {
	depMap := make(map[string][]workflows.WorkflowStepDefinition)

	for _, step := range steps {
		dependencies, err := dv.stepService.GetDependencies(step.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get dependencies for step %s: %w", step.ID.String(), err)
		}

		depMap[step.ID.String()] = dependencies
	}

	return depMap, nil
}

// checkCycles detects cycles and updates the validation result
func (dv *DAGValidator) checkCycles(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition, result *DAGValidationResult) error {
	cycles, err := dv.detectAllCycles(steps, depMap)
	if err != nil {
		return fmt.Errorf("cycle detection failed: %w", err)
	}

	if len(cycles) > 0 {
		result.IsValid = false
		result.Cycles = cycles
		for _, cycle := range cycles {
			result.Errors = append(result.Errors, fmt.Sprintf("circular dependency detected: %s", cycle.Path))
		}
	}

	return nil
}

// detectAllCycles finds all cycles in the workflow DAG
func (dv *DAGValidator) detectAllCycles(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition) ([]DAGCycle, error) {
	var cycles []DAGCycle
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)
	path := make(map[string]string)

	for _, step := range steps {
		if !visited[step.ID.String()] {
			cycle, err := dv.dfsCycleDetection(step.ID, depMap, visited, recursionStack, path)
			if err != nil {
				return nil, err
			}
			if cycle != nil {
				cycles = append(cycles, *cycle)
			}
		}
	}

	return cycles, nil
}

// dfsCycleDetection performs DFS to detect cycles using pre-built dependency map
func (dv *DAGValidator) dfsCycleDetection(
	currentStepID *uuid.UUID,
	depMap map[string][]workflows.WorkflowStepDefinition,
	visited, recursionStack map[string]bool,
	path map[string]string,
) (*DAGCycle, error) {
	currentID := currentStepID.String()
	visited[currentID] = true
	recursionStack[currentID] = true

	// Get dependencies from pre-built map (O(1) lookup)
	dependencies := depMap[currentID]

	for _, dep := range dependencies {
		depID := dep.ID.String()

		// Cycle detected
		if recursionStack[depID] {
			return dv.createCycleResult(currentID, depID, path), nil
		}

		// Recurse if not visited
		if !visited[depID] {
			path[currentID] = depID
			cycle, err := dv.dfsCycleDetection(dep.ID, depMap, visited, recursionStack, path)
			if err != nil {
				return nil, err
			}
			if cycle != nil {
				return cycle, nil
			}
			delete(path, currentID)
		}
	}

	recursionStack[currentID] = false
	return nil, nil
}

// createCycleResult builds a DAGCycle result from detected cycle
func (dv *DAGValidator) createCycleResult(fromID, toID string, path map[string]string) *DAGCycle {
	cyclePath := dv.buildCyclePath(fromID, toID, path)
	cycle := DAGCycle{
		Steps: []string{toID, fromID},
		Path:  cyclePath,
	}

	// Add all steps in the cycle path
	for stepID := range path {
		if path[stepID] != "" {
			cycle.Steps = append(cycle.Steps, stepID)
		}
	}

	return &cycle
}

// buildCyclePath creates a human-readable cycle path
func (dv *DAGValidator) buildCyclePath(fromID, toID string, path map[string]string) string {
	cyclePath := toID
	current := fromID

	for current != "" && current != toID {
		cyclePath += " -> " + current
		current = path[current]
		if current == toID {
			cyclePath += " -> " + toID
			break
		}
	}

	return cyclePath
}

// checkOrphanedSteps detects orphaned steps and updates the validation result
func (dv *DAGValidator) checkOrphanedSteps(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition, result *DAGValidationResult) error {
	orphaned, err := dv.detectOrphanedSteps(steps, depMap)
	if err != nil {
		return fmt.Errorf("orphaned step detection failed: %w", err)
	}

	if len(orphaned) > 0 {
		result.OrphanedSteps = orphaned
		for _, orphan := range orphaned {
			result.Warnings = append(result.Warnings, fmt.Sprintf("orphaned step '%s': %s", orphan.StepName, orphan.Reason))
		}
	}

	return nil
}

// detectOrphanedSteps finds steps with no dependencies or no dependents
func (dv *DAGValidator) detectOrphanedSteps(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition) ([]OrphanedStep, error) {
	var orphaned []OrphanedStep

	// Use helper to count dependents efficiently
	dependents := countDependents(steps, depMap)

	// Find orphaned steps
	for _, step := range steps {
		stepID := step.ID.String()
		dependencies := depMap[stepID]

		// Check if step has no dependencies (isolated starting point)
		if len(dependencies) == 0 && len(steps) > 1 {
			orphaned = append(orphaned, OrphanedStep{
				StepID:   *step.ID,
				StepName: step.Name,
				Reason:   OrphanReasonNoDependencies,
			})
		}

		// Check if step has no dependents (dead-end step)
		if dependents[stepID] == 0 && len(steps) > 1 && len(dependencies) > 0 {
			orphaned = append(orphaned, OrphanedStep{
				StepID:   *step.ID,
				StepName: step.Name,
				Reason:   OrphanReasonNoDependents,
			})
		}
	}

	return orphaned, nil
}

// countDependents counts the number of dependents for each step
func countDependents(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition) map[string]int {
	dependents := make(map[string]int)

	for _, step := range steps {
		stepID := step.ID.String()
		dependencies := depMap[stepID]

		for _, dep := range dependencies {
			dependents[dep.ID.String()]++
		}
	}

	return dependents
}

// checkDependencyIssues validates dependencies and updates the validation result
func (dv *DAGValidator) checkDependencyIssues(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition, result *DAGValidationResult) error {
	issues, err := dv.validateDependencies(steps, depMap)
	if err != nil {
		return fmt.Errorf("dependency validation failed: %w", err)
	}

	if len(issues) > 0 {
		result.Dependencies = issues
		for _, issue := range issues {
			result.Errors = append(result.Errors, fmt.Sprintf("dependency issue: %s", issue.Issue))
		}
		result.IsValid = false
	}

	return nil
}

// validateDependencies performs comprehensive dependency validation
func (dv *DAGValidator) validateDependencies(steps []workflows.WorkflowStepDefinition, depMap map[string][]workflows.WorkflowStepDefinition) ([]DependencyIssue, error) {
	var issues []DependencyIssue
	stepIndex := buildStepIndex(steps)

	for _, step := range steps {
		stepID := step.ID.String()
		dependencies := depMap[stepID]

		for _, dep := range dependencies {
			depID := dep.ID.String()

			// Check for self-dependency
			if stepID == depID {
				issues = append(issues, DependencyIssue{
					FromStepID:   *step.ID,
					FromStepName: step.Name,
					ToStepID:     *dep.ID,
					ToStepName:   step.Name,
					Issue:        fmt.Sprintf("step '%s' depends on itself", step.Name),
				})
				continue
			}

			// Check if dependency step exists in the same workflow (O(1) lookup)
			if _, err := stepIndex.findStep(dep.ID); err != nil {
				issues = append(issues, DependencyIssue{
					FromStepID:   *step.ID,
					FromStepName: step.Name,
					ToStepID:     *dep.ID,
					ToStepName:   "unknown",
					Issue:        fmt.Sprintf("step '%s' depends on non-existent step '%s'", step.Name, depID),
				})
			}
		}
	}

	return issues, nil
}

// ValidateDependencyChange validates adding/removing a specific dependency
func (dv *DAGValidator) ValidateDependencyChange(workflowDefID, stepID, dependsOnStepID *uuid.UUID, isAdd bool) error {
	if isAdd {
		return dv.validateDependencyAddition(stepID, dependsOnStepID)
	}
	return dv.validateDependencyRemoval(stepID, dependsOnStepID)
}

// validateDependencyAddition validates adding a new dependency
func (dv *DAGValidator) validateDependencyAddition(stepID, dependsOnStepID *uuid.UUID) error {
	// Check if it would create a cycle
	hasCycle, err := dv.stepService.HasCircularDependency(stepID, dependsOnStepID)
	if err != nil {
		return fmt.Errorf("cycle detection failed: %w", err)
	}

	if hasCycle {
		return errors.New("adding this dependency would create a circular reference")
	}

	// Check if dependency already exists
	return dv.checkDependencyNotExists(stepID, dependsOnStepID)
}

// validateDependencyRemoval validates removing an existing dependency
func (dv *DAGValidator) validateDependencyRemoval(stepID, dependsOnStepID *uuid.UUID) error {
	return dv.checkDependencyExists(stepID, dependsOnStepID)
}

// checkDependencyExists verifies that a dependency exists
func (dv *DAGValidator) checkDependencyExists(stepID, dependsOnStepID *uuid.UUID) error {
	dependencies, err := dv.stepService.GetDependencies(stepID)
	if err != nil {
		return fmt.Errorf("failed to get current dependencies: %w", err)
	}

	for _, dep := range dependencies {
		if dep.ID.String() == dependsOnStepID.String() {
			return nil
		}
	}

	return errors.New("dependency does not exist")
}

// checkDependencyNotExists verifies that a dependency does not already exist
func (dv *DAGValidator) checkDependencyNotExists(stepID, dependsOnStepID *uuid.UUID) error {
	dependencies, err := dv.stepService.GetDependencies(stepID)
	if err != nil {
		return fmt.Errorf("failed to get current dependencies: %w", err)
	}

	for _, dep := range dependencies {
		if dep.ID.String() == dependsOnStepID.String() {
			return errors.New("dependency already exists")
		}
	}

	return nil
}
