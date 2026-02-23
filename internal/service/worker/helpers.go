package worker

import (
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/service/relational/workflows"
)

type stepTitles struct {
	Step     string
	Workflow string
	Instance string
}

func resolveStepTitles(step *workflows.StepExecution) stepTitles {
	titles := stepTitles{}
	if step == nil {
		return titles
	}

	if step.WorkflowStepDefinition != nil {
		titles.Step = step.WorkflowStepDefinition.Name
	}
	if step.WorkflowExecution != nil && step.WorkflowExecution.WorkflowInstance != nil {
		if step.WorkflowExecution.WorkflowInstance.WorkflowDefinition != nil {
			titles.Workflow = step.WorkflowExecution.WorkflowInstance.WorkflowDefinition.Name
		}
		titles.Instance = step.WorkflowExecution.WorkflowInstance.Name
	}

	return titles
}

func resolveTaskURL(stepURL, webBaseURL string) string {
	if stepURL != "" {
		return stepURL
	}
	return webBaseURL + "/my-tasks"
}

// formatDate formats a time value as "dd/mmm/yyyy" (e.g. "05/mar/2025").
func formatDate(t time.Time) string {
	return strings.ToLower(t.Format("02/Jan/2006"))
}

// formatDueDate formats an optional due date pointer; returns "" when nil.
func formatDueDate(t *time.Time) string {
	if t == nil {
		return ""
	}
	return formatDate(*t)
}
