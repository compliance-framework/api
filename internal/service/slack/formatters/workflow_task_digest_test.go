package formatters

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatWorkflowTaskDigestMessage_WithTasks(t *testing.T) {
	msg, err := FormatWorkflowTaskDigestMessage(
		"Alice Smith",
		"Daily digest - Thursday",
		[]WorkflowTaskDigestItem{
			{
				StepTitle:             "Review Policy",
				WorkflowTitle:         "Annual Audit",
				WorkflowInstanceTitle: "Audit 2026",
				DueDate:               "2026-04-03",
				StepURL:               "https://app.example.com/steps/1",
			},
		},
		[]WorkflowTaskDigestItem{
			{
				StepTitle:     "Upload Evidence",
				WorkflowTitle: "SOC2",
				DueDate:       "2026-04-01",
			},
		},
		"https://app.example.com/my-tasks",
	)

	assert.NoError(t, err)
	assert.NotNil(t, msg)
	assert.NotEmpty(t, msg.Text)
	assert.NotEmpty(t, msg.Blocks)
}

func TestFormatWorkflowTaskDigestMessage_NoTasks(t *testing.T) {
	msg, err := FormatWorkflowTaskDigestMessage(
		"",
		"",
		nil,
		nil,
		"",
	)

	assert.NoError(t, err)
	assert.NotNil(t, msg)
	assert.Equal(t, "Workflow task summary: overdue=0, pending=0", msg.Text)
	assert.NotEmpty(t, msg.Blocks)
}
