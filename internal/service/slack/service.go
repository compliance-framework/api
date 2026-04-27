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

type apiClient interface {
	SendMessageContext(ctx context.Context, channelID string, options ...slack.MsgOption) (string, string, string, error)
	AuthTestContext(ctx context.Context) (*slack.AuthTestResponse, error)
	GetTeamInfoContext(ctx context.Context) (*slack.TeamInfo, error)
	GetBotInfoContext(ctx context.Context, parameters slack.GetBotInfoParameters) (*slack.Bot, error)
}

type WorkspaceConfiguration struct {
	WorkspaceName   string
	WorkspaceURL    string
	WorkspaceDomain string
	EmailDomain     string
	TeamID          string
	BotID           string
	BotName         string
	EnterpriseID    string
}

type Service struct {
	config *config.SlackConfig
	logger *zap.SugaredLogger
	client apiClient
}

func NewService(cfg *config.SlackConfig, logger *zap.SugaredLogger) (*Service, error) {
	service := &Service{
		config: cfg,
		logger: logger,
	}
	if cfg != nil && strings.TrimSpace(cfg.Token) != "" {
		service.client = slack.New(cfg.Token)
	}
	return service, nil
}

func (s *Service) GetConfiguration(ctx context.Context) (WorkspaceConfiguration, error) {
	if s == nil || s.config == nil {
		return WorkspaceConfiguration{}, fmt.Errorf("slack service is not configured")
	}

	return s.GetConfigurationForToken(ctx, s.config.Token)
}

func (s *Service) GetConfigurationForToken(ctx context.Context, token string) (WorkspaceConfiguration, error) {
	if s == nil || s.config == nil {
		return WorkspaceConfiguration{}, fmt.Errorf("slack service is not configured")
	}

	if !s.config.Enabled {
		return WorkspaceConfiguration{}, fmt.Errorf("slack service is not enabled")
	}

	trimmedToken := strings.TrimSpace(token)
	if trimmedToken == "" {
		return WorkspaceConfiguration{}, fmt.Errorf("slack token is required")
	}

	api := s.clientForToken(trimmedToken)
	auth, err := api.AuthTestContext(ctx)
	if err != nil {
		return WorkspaceConfiguration{}, err
	}

	configuration := WorkspaceConfiguration{
		WorkspaceName: strings.TrimSpace(auth.Team),
		WorkspaceURL:  strings.TrimSpace(auth.URL),
		TeamID:        strings.TrimSpace(auth.TeamID),
		BotID:         strings.TrimSpace(auth.BotID),
		EnterpriseID:  strings.TrimSpace(auth.EnterpriseID),
	}

	teamInfo, err := api.GetTeamInfoContext(ctx)
	if err != nil {
		if s != nil && s.logger != nil {
			s.logger.Warnw("Failed to retrieve Slack team info", "error", err)
		}
	} else if teamInfo != nil {
		if name := strings.TrimSpace(teamInfo.Name); name != "" {
			configuration.WorkspaceName = name
		}
		configuration.WorkspaceDomain = strings.TrimSpace(teamInfo.Domain)
		configuration.EmailDomain = strings.TrimSpace(teamInfo.EmailDomain)
	}

	if configuration.BotID == "" {
		return configuration, nil
	}

	botInfo, err := api.GetBotInfoContext(ctx, slack.GetBotInfoParameters{
		Bot:    configuration.BotID,
		TeamID: configuration.TeamID,
	})
	if err != nil {
		if s != nil && s.logger != nil {
			s.logger.Warnw("Failed to retrieve Slack bot info", "error", err, "botID", configuration.BotID)
		}
		return configuration, nil
	}
	if botInfo != nil {
		configuration.BotName = strings.TrimSpace(botInfo.Name)
	}

	return configuration, nil
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

	api := s.clientForToken(s.config.Token)

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

func (s *Service) clientForToken(token string) apiClient {
	trimmedToken := strings.TrimSpace(token)
	if s != nil && s.client != nil && s.config != nil && trimmedToken == strings.TrimSpace(s.config.Token) {
		return s.client
	}

	api := slack.New(trimmedToken)
	if s != nil && s.config != nil && trimmedToken == strings.TrimSpace(s.config.Token) {
		s.client = api
	}

	return api
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
