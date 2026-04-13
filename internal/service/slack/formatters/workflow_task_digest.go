package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

type WorkflowTaskDigestItem struct {
	StepTitle             string
	WorkflowTitle         string
	WorkflowInstanceTitle string
	DueDate               string
	StepURL               string
}

func FormatWorkflowTaskDigestMessage(
	userName string,
	periodLabel string,
	pendingTasks []WorkflowTaskDigestItem,
	overdueTasks []WorkflowTaskDigestItem,
	myTasksURL string,
) (*types.Message, error) {
	const maxOverdueTasksInSlack = 4

	title := strings.TrimSpace(periodLabel)
	if title == "" {
		title = "Daily digest"
	}

	greeting := "Here is your workflow task summary."
	if name := strings.TrimSpace(userName); name != "" {
		greeting = fmt.Sprintf("Hi %s, here is your workflow task summary.", name)
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "Your Task Summary", true, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, greeting, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Period:* %s", title), false, false), nil, nil),
	}

	if len(overdueTasks) > 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Overdue Tasks (%d)*", len(overdueTasks)), false, false),
			nil,
			nil,
		))
		overdueToShow := len(overdueTasks)
		if overdueToShow > maxOverdueTasksInSlack {
			overdueToShow = maxOverdueTasksInSlack
		}
		for i := 0; i < overdueToShow; i++ {
			blocks = append(blocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(slack.MarkdownType, formatWorkflowTaskDigestItem(overdueTasks[i]), false, false),
				nil,
				nil,
			))
		}

		if len(overdueTasks) > overdueToShow {
			blocks = append(blocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(slack.MarkdownType, buildMoreOverdueTasksText(len(overdueTasks)-overdueToShow, myTasksURL, maxOverdueTasksInSlack), false, false),
				nil,
				nil,
			))
		}
	}

	if len(pendingTasks) > 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Pending Tasks (%d)*", len(pendingTasks)), false, false),
			nil,
			nil,
		))
		for i := range pendingTasks {
			blocks = append(blocks, slack.NewSectionBlock(
				slack.NewTextBlockObject(slack.MarkdownType, formatWorkflowTaskDigestItem(pendingTasks[i]), false, false),
				nil,
				nil,
			))
		}
	}

	if len(pendingTasks) == 0 && len(overdueTasks) == 0 {
		blocks = append(blocks, slack.NewDividerBlock())
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, ":white_check_mark: You have no pending or overdue tasks.", false, false),
			nil,
			nil,
		))
	}

	myTasksURL = strings.TrimSpace(myTasksURL)
	if myTasksURL != "" {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("<%s|View all my tasks>", myTasksURL), false, false),
			nil,
			nil,
		))
	}

	return &types.Message{
		Text:   fmt.Sprintf("Workflow task summary: overdue=%d, pending=%d", len(overdueTasks), len(pendingTasks)),
		Blocks: blocks,
	}, nil
}

func buildMoreOverdueTasksText(remaining int, myTasksURL string, maxOverdueTasksInSlack int) string {
	if remaining <= 0 {
		return ""
	}

	moreText := fmt.Sprintf("_Showing %d overdue tasks in Slack. There %s %d more overdue %s._", maxOverdueTasksInSlack, workflowPluralVerb(remaining), remaining, workflowPluralize(remaining, "task", "tasks"))
	myTasksURL = strings.TrimSpace(myTasksURL)
	if myTasksURL == "" {
		return moreText
	}

	return moreText + fmt.Sprintf(" <%s|View all my tasks>", myTasksURL)
}

func workflowPluralVerb(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func workflowPluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

func formatWorkflowTaskDigestItem(task WorkflowTaskDigestItem) string {
	stepTitle := strings.TrimSpace(task.StepTitle)
	if stepTitle == "" {
		stepTitle = "Untitled task"
	}

	workflowTitle := strings.TrimSpace(task.WorkflowTitle)
	if workflowTitle == "" {
		workflowTitle = "Workflow"
	}

	instanceTitle := strings.TrimSpace(task.WorkflowInstanceTitle)
	dueDate := strings.TrimSpace(task.DueDate)
	stepURL := strings.TrimSpace(task.StepURL)

	taskLine := "*" + stepTitle + "*"
	if stepURL != "" {
		taskLine = fmt.Sprintf("*<%s|%s>*", stepURL, stepTitle)
	}

	details := fmt.Sprintf("%s\nWorkflow: %s", taskLine, workflowTitle)
	if instanceTitle != "" {
		details += fmt.Sprintf(" / %s", instanceTitle)
	}
	if dueDate != "" {
		details += fmt.Sprintf("\nDue: %s", dueDate)
	}

	return details
}
