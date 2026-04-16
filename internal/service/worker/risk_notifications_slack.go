package worker

import (
	"context"
	"fmt"

	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	"github.com/slack-go/slack"
)

func renderRiskReviewDueReminderSlack(_ context.Context, model any) (slackprovider.Content, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatRiskReviewDueReminderMessage(
		reminderModel.OwnerName,
		reminderModel.RiskTitle,
		reminderModel.SSPName,
		reminderModel.RiskStatus,
		reminderModel.ReviewDeadline,
		reminderModel.RiskURL,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format risk-review-due-reminder slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}

func renderRiskReviewOverdueEscalationSlack(_ context.Context, model any) (slackprovider.Content, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatRiskReviewOverdueEscalationMessage(
		reminderModel.OwnerName,
		reminderModel.RiskTitle,
		reminderModel.SSPName,
		reminderModel.RiskStatus,
		reminderModel.ReviewDeadline,
		reminderModel.RiskURL,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format risk-review-overdue-escalation slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}

func renderRiskStaleOpenReminderSlack(_ context.Context, model any) (slackprovider.Content, error) {
	reminderModel, err := riskReminderNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatRiskStaleOpenReminderMessage(
		reminderModel.OwnerName,
		reminderModel.RiskTitle,
		reminderModel.SSPName,
		reminderModel.RiskStatus,
		reminderModel.LastSeenAt,
		reminderModel.RiskURL,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format risk-stale-open-reminder slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}

func renderRiskOpenDigestSlack(_ context.Context, model any) (slackprovider.Content, error) {
	digestModel, err := riskOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return slackprovider.Content{}, err
	}

	message, err := slackformatters.FormatRiskOpenDigestMessage(
		digestModel.RecipientName,
		digestModel.PeriodLabel,
		toSlackRiskDigestItems(digestModel.NewSinceLastDigest),
		toSlackRiskDigestItems(digestModel.OverdueForAction),
		toSlackRiskDigestItems(digestModel.StaleRisks),
		toSlackRiskDigestItems(digestModel.OverdueReview),
		toSlackRiskDigestItems(digestModel.DueForReview),
		digestModel.RisksURL,
	)
	if err != nil {
		return slackprovider.Content{}, fmt.Errorf("failed to format risk-open-digest slack message: %w", err)
	}

	return slackprovider.Content{
		Text:   message.Text,
		Blocks: append([]slack.Block(nil), message.Blocks...),
	}, nil
}
