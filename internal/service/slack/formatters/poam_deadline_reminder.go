package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

func FormatPoamDeadlineReminderMessage(
	recipientName string,
	poamTitle string,
	sspName string,
	currentStatus string,
	deadline string,
	milestoneCount int,
	poamURL string,
) (*types.Message, error) {
	title := strings.TrimSpace(poamTitle)
	if title == "" {
		title = "Untitled POAM item"
	}

	ssp := strings.TrimSpace(sspName)
	if ssp == "" {
		ssp = "N/A"
	}

	status := strings.TrimSpace(currentStatus)
	if status == "" {
		status = "N/A"
	}

	greeting := "A Plan of Action & Milestones item assigned to you has an upcoming planned completion date."
	if name := strings.TrimSpace(recipientName); name != "" {
		greeting = fmt.Sprintf("Hi %s, a Plan of Action & Milestones item assigned to you has an upcoming planned completion date.", name)
	}

	details := fmt.Sprintf("*POAM Item:* %s\n*SSP:* %s\n*Current Status:* %s\n*Milestones:* %d", title, ssp, status, milestoneCount)
	if trimmedDeadline := strings.TrimSpace(deadline); trimmedDeadline != "" {
		details += fmt.Sprintf("\n*Planned Completion:* %s", trimmedDeadline)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "POAM Deadline Approaching", true, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, greeting, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, details, false, false), nil, nil),
	}

	poamURL = strings.TrimSpace(poamURL)
	if poamURL != "" {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("<%s|Open POAM Item>", poamURL), false, false),
			nil,
			nil,
		))
	}

	return &types.Message{
		Text:   fmt.Sprintf("POAM deadline approaching: %s", title),
		Blocks: blocks,
	}, nil
}
