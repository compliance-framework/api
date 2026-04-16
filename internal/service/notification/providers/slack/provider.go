package slack

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/notification"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
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
	EnqueueNotificationSlack(ctx context.Context, delivery Delivery) error
}

type SenderProvider func() Sender

type EnqueuerProvider func() Enqueuer

type Provider struct {
	senderProvider   SenderProvider
	enqueuerProvider EnqueuerProvider
}

func NewProvider(senderProvider SenderProvider, enqueuerProvider EnqueuerProvider) *Provider {
	return &Provider{senderProvider: senderProvider, enqueuerProvider: enqueuerProvider}
}

func (p *Provider) ID() string { return ChannelID }

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
		if err := enqueuer.EnqueueNotificationSlack(ctx, providerDelivery); err != nil {
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
