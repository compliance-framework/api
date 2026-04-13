package formatters

import (
	"fmt"
	"strings"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFormatWorkflowTaskDigestMessage_OverdueLimitedToFourWithMoreLink(t *testing.T) {
	overdue := make([]WorkflowTaskDigestItem, 0, 6)
	for i := 1; i <= 6; i++ {
		overdue = append(overdue, WorkflowTaskDigestItem{
			StepTitle:     fmt.Sprintf("Overdue %d", i),
			WorkflowTitle: "SOC2",
		})
	}

	msg, err := FormatWorkflowTaskDigestMessage(
		"Alice",
		"Daily digest",
		nil,
		overdue,
		"https://app.example.com/my-tasks",
	)
	require.NoError(t, err)

	var overdueItemSections int
	var foundMoreNotice bool
	for _, block := range msg.Blocks {
		section, ok := block.(*slack.SectionBlock)
		if !ok || section.Text == nil {
			continue
		}

		text := section.Text.Text
		if strings.Contains(text, "*Overdue ") && strings.Contains(text, "Workflow: SOC2") {
			overdueItemSections++
		}
		if strings.Contains(text, "Showing 4 overdue tasks in Slack") && strings.Contains(text, "View all my tasks") {
			foundMoreNotice = true
		}
	}

	assert.Equal(t, 4, overdueItemSections)
	assert.True(t, foundMoreNotice)
}

func TestFormatWorkflowTaskDigestMessage_OverdueLimitedToFourWithoutMoreLink(t *testing.T) {
	overdue := make([]WorkflowTaskDigestItem, 0, 5)
	for i := 1; i <= 5; i++ {
		overdue = append(overdue, WorkflowTaskDigestItem{
			StepTitle:     fmt.Sprintf("Overdue %d", i),
			WorkflowTitle: "ISO27001",
		})
	}

	msg, err := FormatWorkflowTaskDigestMessage(
		"Alice",
		"Daily digest",
		nil,
		overdue,
		"",
	)
	require.NoError(t, err)

	var foundMoreNotice bool
	for _, block := range msg.Blocks {
		section, ok := block.(*slack.SectionBlock)
		if !ok || section.Text == nil {
			continue
		}

		text := section.Text.Text
		if strings.Contains(text, "There is 1 more overdue task") && !strings.Contains(text, "View all my tasks") {
			foundMoreNotice = true
		}
	}

	assert.True(t, foundMoreNotice)
}
