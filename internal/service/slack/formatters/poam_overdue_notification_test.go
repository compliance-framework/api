package formatters

import (
	"strings"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatPoamOverdueNotificationMessage(t *testing.T) {
	msg, err := FormatPoamOverdueNotificationMessage(
		"Bob Jones",
		"Patch Vulnerable Dependencies",
		"CoreBanking SSP",
		"2026-04-15T00:00:00Z",
		"https://app.example.com/poam-items/456",
	)
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "POAM overdue")
	require.Len(t, msg.Blocks, 4)

	var foundLink bool
	for _, block := range msg.Blocks {
		if section, ok := block.(*slack.SectionBlock); ok && section.Text != nil && strings.Contains(section.Text.Text, "Open POAM Item") {
			foundLink = true
			break
		}
	}
	assert.True(t, foundLink)
}

func TestFormatPoamOverdueNotificationMessage_DefaultsMissingFields(t *testing.T) {
	msg, err := FormatPoamOverdueNotificationMessage("", "", "", "", "")
	require.NoError(t, err)
	assert.Contains(t, msg.Text, "Untitled POAM item")
	require.Len(t, msg.Blocks, 3)
}
