package worker

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
	"github.com/stretchr/testify/require"
)

func TestResolveStepTitles(t *testing.T) {
	t.Parallel()

	t.Run("nil step", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, stepTitles{}, resolveStepTitles(nil))
	})

	t.Run("partial preload", func(t *testing.T) {
		t.Parallel()
		step := &workflows.StepExecution{
			WorkflowStepDefinition: &workflows.WorkflowStepDefinition{Name: "Collect Evidence"},
		}

		require.Equal(t, stepTitles{
			Step: "Collect Evidence",
		}, resolveStepTitles(step))
	})

	t.Run("fully preloaded", func(t *testing.T) {
		t.Parallel()
		step := &workflows.StepExecution{
			WorkflowStepDefinition: &workflows.WorkflowStepDefinition{Name: "Collect Evidence"},
			WorkflowExecution: &workflows.WorkflowExecution{
				WorkflowInstance: &workflows.WorkflowInstance{
					Name:               "Q1 2026 Access Review",
					WorkflowDefinition: &workflows.WorkflowDefinition{Name: "Access Review"},
				},
			},
		}

		require.Equal(t, stepTitles{
			Step:     "Collect Evidence",
			Workflow: "Access Review",
			Instance: "Q1 2026 Access Review",
		}, resolveStepTitles(step))
	})
}

func TestNotificationUserFullName(t *testing.T) {
	t.Parallel()

	t.Run("first name only", func(t *testing.T) {
		t.Parallel()
		user := NotificationUser{FirstName: "Alice"}
		require.Equal(t, "Alice", user.FullName())
	})

	t.Run("first and last name", func(t *testing.T) {
		t.Parallel()
		user := NotificationUser{FirstName: "Alice", LastName: "Smith"}
		require.Equal(t, "Alice Smith", user.FullName())
	})

	t.Run("last name only preserves existing behavior", func(t *testing.T) {
		t.Parallel()
		user := NotificationUser{LastName: "Smith"}
		require.Equal(t, " Smith", user.FullName())
	})
}

func TestResolveTaskURL(t *testing.T) {
	t.Parallel()

	t.Run("uses step URL when present", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "https://app.example.com/steps/123", resolveTaskURL("https://app.example.com/steps/123", "https://app.example.com"))
	})

	t.Run("falls back to my tasks URL", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "https://app.example.com/my-tasks", resolveTaskURL("", "https://app.example.com"))
	})
}
