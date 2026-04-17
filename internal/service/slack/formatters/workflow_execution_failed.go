package formatters

import (
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

func FormatWorkflowExecutionFailedMessage(
	recipientName string,
	workflowTitle string,
	workflowInstanceName string,
	executionID string,
	failureReason string,
	failedAt string,
	failedSteps int,
	completedSteps int,
	totalSteps int,
	workflowURL string,
	myTasksURL string,
) (*types.Message, error) {
	workflow := strings.TrimSpace(workflowTitle)
	if workflow == "" {
		workflow = "Workflow"
	}

	instance := strings.TrimSpace(workflowInstanceName)
	if instance == "" {
		instance = workflow
	}

	reason := strings.TrimSpace(failureReason)
	if reason == "" {
		reason = "No failure reason provided."
	}

	greeting := "A workflow execution has failed and may require your attention."
	if name := strings.TrimSpace(recipientName); name != "" {
		greeting = fmt.Sprintf("Hi %s, a workflow execution has failed and may require your attention.", name)
	}

	summary := fmt.Sprintf("*Instance:* %s\n*Workflow:* %s\n*Failed Steps:* %d\n*Completed Steps:* %d\n*Total Steps:* %d", instance, workflow, failedSteps, completedSteps, totalSteps)

	details := []string{}
	if trimmedExecutionID := strings.TrimSpace(executionID); trimmedExecutionID != "" {
		details = append(details, fmt.Sprintf("*Execution ID:* %s", trimmedExecutionID))
	}
	if trimmedFailedAt := strings.TrimSpace(failedAt); trimmedFailedAt != "" {
		details = append(details, fmt.Sprintf("*Failed At:* %s", trimmedFailedAt))
	}

	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "Workflow Execution Failed", true, false)),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, greeting, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, summary, false, false), nil, nil),
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Failure Reason:*\n```%s```", reason), false, false), nil, nil),
	}

	if len(details) > 0 {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, strings.Join(details, "\n"), false, false),
			nil,
			nil,
		))
	}

	links := []string{}
	if trimmedWorkflowURL := strings.TrimSpace(workflowURL); trimmedWorkflowURL != "" {
		links = append(links, fmt.Sprintf("<%s|View Workflow Instance>", trimmedWorkflowURL))
	}
	if trimmedMyTasksURL := strings.TrimSpace(myTasksURL); trimmedMyTasksURL != "" {
		links = append(links, fmt.Sprintf("<%s|View My Tasks>", trimmedMyTasksURL))
	}
	if len(links) > 0 {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject(slack.MarkdownType, strings.Join(links, "\n"), false, false),
			nil,
			nil,
		))
	}

	return &types.Message{
		Text:   fmt.Sprintf("Workflow execution failed: %s", instance),
		Blocks: blocks,
	}, nil
}
