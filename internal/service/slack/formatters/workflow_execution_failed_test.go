package formatters

import (
	"strings"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatWorkflowExecutionFailedMessage(t *testing.T) {
	msg, err := FormatWorkflowExecutionFailedMessage(
		"Alice Smith",
		"Annual Audit",
		"Audit 2026",
		"exec-123",
		"step execution failed",
		"17 Apr 2026",
		1,
		3,
		4,
		"https://app.example.com/my-tasks",
		"https://app.example.com/my-tasks",
	)
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Workflow execution failed")
	require.NotEmpty(t, msg.Blocks)

	var foundReason bool
	for _, block := range msg.Blocks {
		if section, ok := block.(*slack.SectionBlock); ok && section.Text != nil && strings.Contains(section.Text.Text, "Failure Reason") {
			foundReason = true
			break
		}
	}
	assert.True(t, foundReason)
}

func TestFormatWorkflowExecutionFailedMessage_DefaultsMissingFields(t *testing.T) {
	msg, err := FormatWorkflowExecutionFailedMessage("", "", "", "", "", "", 0, 0, 0, "", "")
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Workflow execution failed: Workflow")
	require.NotEmpty(t, msg.Blocks)
}
