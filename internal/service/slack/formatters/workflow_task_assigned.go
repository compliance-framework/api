package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

func FormatWorkflowTaskAssignedMessage(
	userName string,
	stepTitle string,
	workflowTitle string,
	workflowInstanceTitle string,
	stepURL string,
	dueDate string,
) (*types.Message, error) {
	stepTitle = strings.TrimSpace(stepTitle)
	if stepTitle == "" {
		stepTitle = "Untitled task"
	}

	workflowTitle = strings.TrimSpace(workflowTitle)
	if workflowTitle == "" {
		workflowTitle = "Workflow"
	}

	instanceTitle := strings.TrimSpace(workflowInstanceTitle)
	if instanceTitle == "" {
		instanceTitle = "N/A"
	}

	greeting := "A workflow task has been assigned to you and is ready for action."
	if name := strings.TrimSpace(userName); name != "" {
		greeting = fmt.Sprintf("Hi %s, a workflow task has been assigned to you and is ready for action.", name)
	}

	details := fmt.Sprintf("*Task:* %s\n*Workflow:* %s\n*Instance:* %s", stepTitle, workflowTitle, instanceTitle)
	dueDate = strings.TrimSpace(dueDate)
	if dueDate != "" {
		details += fmt.Sprintf("\n*Due Date:* %s", dueDate)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "Task Ready for You", true, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, greeting, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, details, false, false), nil, nil),
	}

	stepURL = strings.TrimSpace(stepURL)
	if stepURL != "" {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("<%s|View Task>", stepURL), false, false),
			nil,
			nil,
		))
	}

	fallback := fmt.Sprintf("Task ready for you: %s (%s)", stepTitle, workflowTitle)
	return &types.Message{Text: fallback, Blocks: blocks}, nil
}
