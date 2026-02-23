package workflow

import "github.com/compliance-framework/api/internal/service/relational/workflows"

// ResolveGraceDays returns the effective grace period days for a workflow instance,
// falling back through: instance → definition → provided default.
func ResolveGraceDays(instance *workflows.WorkflowInstance, defaultDays int) int {
	if instance == nil {
		return defaultDays
	}
	if instance.GracePeriodDays != nil {
		return *instance.GracePeriodDays
	}
	if instance.WorkflowDefinition != nil && instance.WorkflowDefinition.GracePeriodDays != nil {
		return *instance.WorkflowDefinition.GracePeriodDays
	}
	return defaultDays
}
