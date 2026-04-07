package formatters

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatWorkflowTaskDueSoonMessage_WithDetails(t *testing.T) {
	msg, err := FormatWorkflowTaskDueSoonMessage(
		"Alice Smith",
		"Review Policy",
		"Annual Audit",
		"Audit 2026",
		"https://app.example.com/steps/1",
		"07/apr/2026",
	)

	assert.NoError(t, err)
	assert.NotNil(t, msg)
	assert.Equal(t, "Task due soon: Review Policy (Annual Audit)", msg.Text)
	assert.NotEmpty(t, msg.Blocks)
}

func TestFormatWorkflowTaskDueSoonMessage_DefaultsMissingFields(t *testing.T) {
	msg, err := FormatWorkflowTaskDueSoonMessage(
		"",
		" ",
		" ",
		" ",
		"",
		"",
	)

	assert.NoError(t, err)
	assert.NotNil(t, msg)
	assert.Equal(t, "Task due soon: Untitled task (Workflow)", msg.Text)
	assert.NotEmpty(t, msg.Blocks)
}
