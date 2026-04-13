package formatters

import (
	"strings"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatRiskReviewDueReminderMessage(t *testing.T) {
	msg, err := FormatRiskReviewDueReminderMessage(
		"Jane Owner",
		"Credential exposure",
		"Payments SSP",
		"risk_accepted",
		"14 Apr 2026",
		"https://app.example.com/risks/123",
	)
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Risk Review Due Soon")
	require.Len(t, msg.Blocks, 4)
}

func TestFormatRiskReviewOverdueEscalationMessage(t *testing.T) {
	msg, err := FormatRiskReviewOverdueEscalationMessage(
		"Jane Owner",
		"Credential exposure",
		"Payments SSP",
		"risk_accepted",
		"11 Apr 2026",
		"https://app.example.com/risks/123",
	)
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Risk Review Overdue")
	require.Len(t, msg.Blocks, 4)
}

func TestFormatRiskStaleOpenReminderMessage(t *testing.T) {
	msg, err := FormatRiskStaleOpenReminderMessage(
		"Jane Owner",
		"Credential exposure",
		"Payments SSP",
		"open",
		"01 Mar 2026",
		"https://app.example.com/risks/123",
	)
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Stale Risk Reminder")
	require.Len(t, msg.Blocks, 4)
}

func TestFormatRiskOpenDigestMessage(t *testing.T) {
	msg, err := FormatRiskOpenDigestMessage(
		"Jane Owner",
		"Daily digest — 13 Apr 2026",
		[]RiskDigestItem{{
			Title:          "Fresh risk",
			SSPName:        "Payments SSP",
			Status:         "open",
			Severity:       "moderate x high",
			OwnerName:      "Jane Owner",
			ReviewDeadline: "14 Apr 2026",
			RiskURL:        "https://app.example.com/risks/1",
		}},
		[]RiskDigestItem{{
			Title:   "Overdue risk",
			SSPName: "Payments SSP",
			Status:  "investigating",
			RiskURL: "https://app.example.com/risks/2",
		}},
		nil,
		nil,
		nil,
		"https://app.example.com/risks",
	)
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Risk digest:")
	require.NotEmpty(t, msg.Blocks)

	var foundViewAll bool
	for _, block := range msg.Blocks {
		if section, ok := block.(*slack.SectionBlock); ok && section.Text != nil && strings.Contains(section.Text.Text, "View all risks") {
			foundViewAll = true
			break
		}
	}
	assert.True(t, foundViewAll)
}
