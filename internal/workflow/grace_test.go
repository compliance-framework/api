package workflow

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/stretchr/testify/assert"
)

func TestResolveGraceDays_NilInstance(t *testing.T) {
	assert.Equal(t, 7, ResolveGraceDays(nil, 7))
}

func TestResolveGraceDays_InstanceOverride(t *testing.T) {
	days := 3
	instance := &workflows.WorkflowInstance{
		GracePeriodDays: &days,
		WorkflowDefinition: &workflows.WorkflowDefinition{
			GracePeriodDays: intPtr(14),
		},
	}
	assert.Equal(t, 3, ResolveGraceDays(instance, 7))
}

func TestResolveGraceDays_DefinitionFallback(t *testing.T) {
	instance := &workflows.WorkflowInstance{
		WorkflowDefinition: &workflows.WorkflowDefinition{
			GracePeriodDays: intPtr(14),
		},
	}
	assert.Equal(t, 14, ResolveGraceDays(instance, 7))
}

func TestResolveGraceDays_DefaultFallback(t *testing.T) {
	instance := &workflows.WorkflowInstance{}
	assert.Equal(t, 7, ResolveGraceDays(instance, 7))
}

func intPtr(i int) *int { return &i }
