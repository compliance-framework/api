package slack

import (
	"context"
	"fmt"

	"github.com/compliance-framework/api/internal/service/notification"
	slackformatters "github.com/compliance-framework/api/internal/service/slack/formatters"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	goslack "github.com/slack-go/slack"
)

type Message = slacktypes.Message

type DigestSummary = slackformatters.DigestSummary

type DigestSummaryEvidence = slackformatters.DigestSummaryEvidence

type RiskDigestItem = slackformatters.RiskDigestItem

type WorkflowTaskDigestItem = slackformatters.WorkflowTaskDigestItem

var (
	FormatDigestMessage                      = slackformatters.FormatDigestMessage
	FormatPoamDeadlineReminderMessage        = slackformatters.FormatPoamDeadlineReminderMessage
	FormatPoamOverdueNotificationMessage     = slackformatters.FormatPoamOverdueNotificationMessage
	FormatRiskReviewDueReminderMessage       = slackformatters.FormatRiskReviewDueReminderMessage
	FormatRiskReviewOverdueEscalationMessage = slackformatters.FormatRiskReviewOverdueEscalationMessage
	FormatRiskStaleOpenReminderMessage       = slackformatters.FormatRiskStaleOpenReminderMessage
	FormatRiskOpenDigestMessage              = slackformatters.FormatRiskOpenDigestMessage
	FormatWorkflowTaskAssignedMessage        = slackformatters.FormatWorkflowTaskAssignedMessage
	FormatWorkflowTaskDueSoonMessage         = slackformatters.FormatWorkflowTaskDueSoonMessage
	FormatWorkflowTaskDigestMessage          = slackformatters.FormatWorkflowTaskDigestMessage
)

func MessageRenderer(renderer func(ctx context.Context, model any) (*Message, error)) notification.ChannelRenderer {
	return notification.ProviderRenderer(ChannelID, func(ctx context.Context, model any) (any, error) {
		message, err := renderer(ctx, model)
		if err != nil {
			return nil, err
		}

		return ContentFromMessage(message)
	})
}

func MessageChannel(renderer func(ctx context.Context, model any) (*Message, error)) notification.RendererBinding {
	return notification.BindRenderer(ChannelID, MessageRenderer(renderer))
}

func ContentFromMessage(message *Message) (Content, error) {
	if message == nil {
		return Content{}, fmt.Errorf("missing slack message")
	}

	return Content{
		Text:   message.Text,
		Blocks: append([]goslack.Block(nil), message.Blocks...),
	}, nil
}
