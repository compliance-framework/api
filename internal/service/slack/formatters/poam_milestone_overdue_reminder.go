package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

func FormatPoamMilestoneOverdueReminderMessage(
	recipientName string,
	milestoneTitle string,
	poamTitle string,
	sspName string,
	dueDate string,
	poamURL string,
) (*types.Message, error) {
	title := strings.TrimSpace(milestoneTitle)
	if title == "" {
		title = "Untitled milestone"
	}

	poamItemTitle := strings.TrimSpace(poamTitle)
	if poamItemTitle == "" {
		poamItemTitle = "Untitled POAM item"
	}

	ssp := strings.TrimSpace(sspName)
	if ssp == "" {
		ssp = "N/A"
	}

	greeting := "A milestone within a Plan of Action & Milestones item has passed its due date without being completed."
	if name := strings.TrimSpace(recipientName); name != "" {
		greeting = fmt.Sprintf("Hi %s, a milestone within a Plan of Action & Milestones item has passed its due date without being completed.", name)
	}

	details := fmt.Sprintf("*Milestone:* %s\n*POAM Item:* %s\n*SSP:* %s", title, poamItemTitle, ssp)
	if trimmedDueDate := strings.TrimSpace(dueDate); trimmedDueDate != "" {
		details += fmt.Sprintf("\n*Due Date:* %s", trimmedDueDate)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "POAM Milestone Overdue", true, false)),
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
		Text:   fmt.Sprintf("POAM milestone overdue: %s", title),
		Blocks: blocks,
	}, nil
}
