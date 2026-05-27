package slack

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	slacksvc "github.com/compliance-framework/api/internal/service/slack"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
)

const (
	TargetTypeChannel               = "channel"
	TargetTypeDirectMessage         = "direct_message"
	ConfiguredDestinationDigestChan = "slack.digest_channel"
)

type Content struct {
	Text   string
	Blocks []slack.Block
}

func (c Content) Validate() error {
	if strings.TrimSpace(c.Text) == "" && len(c.Blocks) == 0 {
		return fmt.Errorf("%w: slack content requires text or blocks", notification.ErrInvalidContent)
	}
	return nil
}

func (c Content) Clone() Content {
	cloned := c
	if len(c.Blocks) > 0 {
		cloned.Blocks = append([]slack.Block(nil), c.Blocks...)
	}
	return cloned
}

func (c Content) ClonePayload() any {
	return c.Clone()
}

type Delivery struct {
	Channel    string
	TargetType string
	Content    Content
	Metadata   notification.TransportMetadata
}

func (d Delivery) Validate() error {
	if strings.TrimSpace(d.Channel) == "" {
		return fmt.Errorf("%w: slack delivery requires channel", notification.ErrInvalidTarget)
	}
	if _, ok := NormalizeTargetType(d.TargetType); !ok {
		return fmt.Errorf("%w: slack delivery requires a supported target type", notification.ErrInvalidTarget)
	}
	return d.Content.Validate()
}

type Sender interface {
	IsEnabled() bool
	SendMessage(ctx context.Context, channel string, message *slacktypes.Message) (*slacktypes.SendResult, error)
}

type Enqueuer interface {
	IsStarted() bool
	EnqueueNotificationSlack(ctx context.Context, delivery Delivery) ([]int64, error)
}

type SenderProvider func() Sender

type EnqueuerProvider func() Enqueuer

type WorkspaceConfigurationResolver func(context.Context) (slacksvc.WorkspaceConfiguration, error)

type EnabledResolver func() bool

type ProviderOption func(*Provider)

type Provider struct {
	senderProvider                 SenderProvider
	enqueuerProvider               EnqueuerProvider
	enabledResolver                EnabledResolver
	workspaceConfigurationResolver WorkspaceConfigurationResolver
	workspaceConfigurationMu       sync.Mutex
	workspaceConfigurationLoaded   bool
	workspaceConfiguration         slacksvc.WorkspaceConfiguration
	workspaceConfigurationErr      error
}

const (
	MetadataKeyWorkspaceName   = "workspace-name"
	MetadataKeyWorkspaceURL    = "workspace-url"
	MetadataKeyWorkspaceDomain = "workspace-domain"
	MetadataKeyEmailDomain     = "email-domain"
	MetadataKeyTeamID          = "team-id"
	MetadataKeyBotID           = "bot-id"
	MetadataKeyBotName         = "bot-name"
	MetadataKeyEnterpriseID    = "enterprise-id"
)

func NewCatalogProvider(cfg *config.Config) *Provider {
	return NewProvider(
		nil,
		nil,
		WithEnabledResolver(func() bool {
			return slackEnabledFromConfig(cfg)
		}),
		WithWorkspaceConfigurationResolver(func(ctx context.Context) (slacksvc.WorkspaceConfiguration, error) {
			if cfg == nil || cfg.Slack == nil || !cfg.Slack.Enabled || strings.TrimSpace(cfg.Slack.Token) == "" {
				return slacksvc.WorkspaceConfiguration{}, nil
			}

			service, err := slacksvc.NewService(cfg.Slack, zap.NewNop().Sugar())
			if err != nil {
				return slacksvc.WorkspaceConfiguration{}, err
			}

			return service.GetConfiguration(ctx)
		}),
	)
}

func NewProvider(senderProvider SenderProvider, enqueuerProvider EnqueuerProvider, opts ...ProviderOption) *Provider {
	provider := &Provider{senderProvider: senderProvider, enqueuerProvider: enqueuerProvider}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	return provider
}

func (p *Provider) ID() string { return ChannelID }

func WithEnabledResolver(resolver EnabledResolver) ProviderOption {
	return func(provider *Provider) {
		if provider == nil {
			return
		}
		provider.enabledResolver = resolver
	}
}

func WithWorkspaceConfigurationResolver(resolver WorkspaceConfigurationResolver) ProviderOption {
	return func(provider *Provider) {
		if provider == nil {
			return
		}
		provider.workspaceConfigurationResolver = resolver
	}
}

func (p *Provider) ProviderMetadata() notification.ProviderMetadata {
	metadata := notification.ProviderMetadata{
		ProviderType: ChannelID,
		DisplayName:  "Slack",
		Description:  "Configured Slack workspace",
		Enabled:      p.enabled(),
	}

	configuration, err := p.workspaceConfigurationDetails()
	if err != nil {
		metadata.Error = err.Error()
	}
	if configuration.WorkspaceName != "" {
		metadata.Description = fmt.Sprintf("Configured Slack workspace %s", configuration.WorkspaceName)
	}

	metadataMap := map[string]string{}
	if configuration.WorkspaceName != "" {
		metadataMap[MetadataKeyWorkspaceName] = configuration.WorkspaceName
	}
	if configuration.WorkspaceURL != "" {
		metadataMap[MetadataKeyWorkspaceURL] = configuration.WorkspaceURL
	}
	if configuration.WorkspaceDomain != "" {
		metadataMap[MetadataKeyWorkspaceDomain] = configuration.WorkspaceDomain
	}
	if configuration.EmailDomain != "" {
		metadataMap[MetadataKeyEmailDomain] = configuration.EmailDomain
	}
	if configuration.TeamID != "" {
		metadataMap[MetadataKeyTeamID] = configuration.TeamID
	}
	if configuration.BotID != "" {
		metadataMap[MetadataKeyBotID] = configuration.BotID
	}
	if configuration.BotName != "" {
		metadataMap[MetadataKeyBotName] = configuration.BotName
	}
	if configuration.EnterpriseID != "" {
		metadataMap[MetadataKeyEnterpriseID] = configuration.EnterpriseID
	}
	if len(metadataMap) > 0 {
		metadata.Metadata = metadataMap
	}

	return metadata
}

func slackEnabledFromConfig(cfg *config.Config) bool {
	return cfg != nil && cfg.Slack != nil && cfg.Slack.Enabled
}

func (p *Provider) enabled() bool {
	if p != nil && p.enabledResolver != nil {
		return p.enabledResolver()
	}

	sender := p.sender()
	return sender != nil && sender.IsEnabled()
}

func (p *Provider) workspaceConfigurationDetails() (slacksvc.WorkspaceConfiguration, error) {
	if p == nil || p.workspaceConfigurationResolver == nil {
		return slacksvc.WorkspaceConfiguration{}, nil
	}

	p.workspaceConfigurationMu.Lock()
	defer p.workspaceConfigurationMu.Unlock()

	if p.workspaceConfigurationLoaded {
		return p.workspaceConfiguration, p.workspaceConfigurationErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	configuration, err := p.workspaceConfigurationResolver(ctx)
	if err != nil {
		p.workspaceConfigurationErr = err
		return p.workspaceConfiguration, err
	}

	p.workspaceConfiguration = configuration
	p.workspaceConfigurationErr = nil
	p.workspaceConfigurationLoaded = true
	return p.workspaceConfiguration, nil
}

func (p *Provider) ResolveUserTarget(user notification.User) (notification.Target, bool, error) {
	if len(user.Identities) == 0 {
		return notification.Target{}, false, nil
	}

	identity, ok := user.Identities[ChannelID]
	if !ok || len(identity) == 0 {
		return notification.Target{}, false, nil
	}

	address := make(map[string]string, len(identity))
	for key, value := range identity {
		address[key] = strings.TrimSpace(value)
	}
	if _, ok := address["target_type"]; !ok {
		address["target_type"] = TargetTypeDirectMessage
	}

	return notification.Target{
		Provider: ChannelID,
		UserID:   user.ID,
		Address:  address,
	}, true, nil
}

func (p *Provider) BuildTarget(rawTarget string) (notification.Target, error) {
	return p.NormalizeTarget(notification.Target{
		Provider: ChannelID,
		Address: map[string]string{
			AddressKeyChannel:    rawTarget,
			AddressKeyTargetType: TargetTypeChannel,
		},
	})
}

func (p *Provider) NormalizeTarget(target notification.Target) (notification.Target, error) {
	channel := strings.TrimSpace(target.Address[AddressKeyChannel])
	if channel == "" {
		return notification.Target{}, fmt.Errorf("%w: slack provider requires channel address", notification.ErrInvalidTarget)
	}

	targetType, ok := NormalizeTargetType(target.Address[AddressKeyTargetType])
	if !ok {
		return notification.Target{}, fmt.Errorf("%w: slack target requires a supported target type", notification.ErrInvalidTarget)
	}

	normalized := notification.Target{
		Provider: ChannelID,
		UserID:   strings.TrimSpace(target.UserID),
		Address: map[string]string{
			AddressKeyChannel:    channel,
			AddressKeyTargetType: targetType,
		},
	}
	if err := p.ValidateTarget(normalized); err != nil {
		return notification.Target{}, err
	}

	return normalized, nil
}

func (p *Provider) DisplayTarget(target notification.Target) (string, error) {
	normalized, err := p.NormalizeTarget(target)
	if err != nil {
		return "", err
	}

	return normalized.Address[AddressKeyChannel], nil
}

func (p *Provider) ValidateTarget(target notification.Target) error {
	channel := strings.TrimSpace(target.Address["channel"])
	if channel == "" {
		return fmt.Errorf("%w: slack provider requires channel address", notification.ErrInvalidTarget)
	}

	targetType, ok := target.Attribute("target_type")
	if !ok {
		return fmt.Errorf("%w: slack target requires target_type attribute", notification.ErrInvalidTarget)
	}
	if _, ok := NormalizeTargetType(targetType); !ok {
		return fmt.Errorf("%w: slack target requires a supported target type", notification.ErrInvalidTarget)
	}

	return nil
}

// Deliver prefers enqueuing when a started enqueuer is available. If direct
// sending is the only option and no sender is configured or enabled, delivery
// is treated as a no-op so notifications can be optional in some environments.
func (p *Provider) Deliver(ctx context.Context, delivery notification.Delivery) error {
	slackContent, err := extractContent(delivery.Content.Payload)
	if err != nil {
		return err
	}

	targetType, _ := delivery.Target.Attribute("target_type")
	providerDelivery := Delivery{
		Channel:    strings.TrimSpace(delivery.Target.Address["channel"]),
		TargetType: targetType,
		Content:    slackContent,
		Metadata:   delivery.Metadata,
	}
	if err := providerDelivery.Validate(); err != nil {
		return err
	}

	if enqueuer := p.enqueuer(); enqueuer != nil && enqueuer.IsStarted() {
		if _, err := enqueuer.EnqueueNotificationSlack(ctx, providerDelivery); err != nil {
			return fmt.Errorf("enqueue slack delivery: %w", err)
		}
		return nil
	}

	sender := p.sender()
	if sender == nil || !sender.IsEnabled() {
		return nil
	}

	message := &slacktypes.Message{
		Text:   providerDelivery.Content.Text,
		Blocks: append([]slack.Block(nil), providerDelivery.Content.Blocks...),
	}

	result, err := sender.SendMessage(ctx, providerDelivery.Channel, message)
	if err != nil {
		return fmt.Errorf("send slack delivery: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("slack delivery send failed: %s", result.Error)
	}

	return nil
}

func (p *Provider) sender() Sender {
	if p == nil || p.senderProvider == nil {
		return nil
	}
	return p.senderProvider()
}

func (p *Provider) enqueuer() Enqueuer {
	if p == nil || p.enqueuerProvider == nil {
		return nil
	}
	return p.enqueuerProvider()
}

func extractContent(payload any) (Content, error) {
	switch typed := payload.(type) {
	case Content:
		return typed.Clone(), nil
	case *Content:
		if typed == nil {
			return Content{}, fmt.Errorf("missing slack content")
		}
		return typed.Clone(), nil
	default:
		return Content{}, fmt.Errorf("slack provider expects slack.Content payload, got %T", payload)
	}
}

func NormalizeTargetType(target string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case TargetTypeChannel:
		return TargetTypeChannel, true
	case TargetTypeDirectMessage, "directmessage", "dm":
		return TargetTypeDirectMessage, true
	default:
		return "", false
	}
}
