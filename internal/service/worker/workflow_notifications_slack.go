package worker

import (
	"context"
	"fmt"

	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	"github.com/slack-go/slack"
)

func renderWorkflowTaskAssignedSlack(_ context.Context, model any) (slackprovider.Content, error) {
	assignedModel, err := workflowTaskAssignedNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatWorkflowTaskAssignedMessage(
		assignedModel.UserName,
		assignedModel.StepTitle,
		assignedModel.WorkflowTitle,
		assignedModel.WorkflowInstanceTitle,
		assignedModel.StepURL,
		assignedModel.DueDate,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format workflow-task-assigned slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}

func renderWorkflowTaskDueSoonSlack(_ context.Context, model any) (slackprovider.Content, error) {
	dueSoonModel, err := workflowTaskDueSoonNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatWorkflowTaskDueSoonMessage(
		dueSoonModel.UserName,
		dueSoonModel.StepTitle,
		dueSoonModel.WorkflowTitle,
		dueSoonModel.WorkflowInstanceTitle,
		dueSoonModel.StepURL,
		dueSoonModel.DueDate,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format workflow-task-due-soon slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}

func renderWorkflowTaskDigestSlack(_ context.Context, model any) (slackprovider.Content, error) {
	digestModel, err := workflowTaskDigestNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatWorkflowTaskDigestMessage(
		digestModel.UserName,
		digestModel.PeriodLabel,
		toSlackDigestTasks(digestModel.PendingTasks),
		toSlackDigestTasks(digestModel.OverdueTasks),
		digestModel.MyTasksURL,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format workflow-task-digest slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}
