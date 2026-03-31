package slack

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
)

type Service struct {
	config *config.SlackConfig
	logger *zap.SugaredLogger
}

func NewService(cfg *config.SlackConfig, logger *zap.SugaredLogger) (*Service, error) {
	return &Service{
		config: cfg,
		logger: logger,
	}, nil
}

func (s *Service) SendMessage(ctx context.Context, channel string, message *types.Message) (*types.SendResult, error) {
	if s == nil || s.config == nil {
		err := fmt.Errorf("slack service is not configured")
		return sendFailureResult(err), err
	}
	if strings.TrimSpace(s.config.Token) == "" {
		err := fmt.Errorf("slack token is required")
		return sendFailureResult(err), err
	}
	if err := validateSendInput(channel, message); err != nil {
		return sendFailureResult(err), err
	}

	api := slack.New(s.config.Token)

	opts := []slack.MsgOption{
		slack.MsgOptionText(message.Text, false),
	}
	if len(message.Blocks) > 0 {
		opts = append(opts, slack.MsgOptionBlocks(message.Blocks...))
	}

	respChannel, respID, respText, err := api.SendMessageContext(ctx, channel, opts...)
	if err != nil {
		s.logger.Errorw("Failed to send Slack message", "channel", channel, "error", err)
		return sendFailureResult(err), err
	}

	resultMessage := fmt.Sprintf("Slack message sent to %s (id: %s)", respChannel, respID)
	s.logger.Debugw("Slack message sent", "channel", respChannel, "delivery_id", respID)

	return &types.SendResult{
		Success:      true,
		Message:      resultMessage,
		Channel:      respChannel,
		DeliveryID:   respID,
		ResponseText: respText,
	}, nil
}

// IsEnabled returns true if the slack service is enabled
func (s *Service) IsEnabled() bool {
	return s.config != nil && s.config.Enabled
}

func validateSendInput(channel string, message *types.Message) error {
	if message == nil {
		return fmt.Errorf("message is required")
	}
	if strings.TrimSpace(channel) == "" {
		return fmt.Errorf("channel is required")
	}
	return nil
}

func sendFailureResult(err error) *types.SendResult {
	return &types.SendResult{
		Success: false,
		Message: "Slack message send failed",
		Error:   err.Error(),
	}
}
