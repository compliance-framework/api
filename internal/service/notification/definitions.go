package notification

import (
	"context"
	"fmt"
	"strings"
)

type ChannelRenderer func(ctx context.Context, model any) (Content, error)

func EmailChannelRenderer(renderer func(ctx context.Context, model any) (EmailContent, error)) ChannelRenderer {
	return func(ctx context.Context, model any) (Content, error) {
		email, err := renderer(ctx, model)
		if err != nil {
			return Content{}, err
		}
		return Content{Channel: DeliveryChannelEmail, Email: &email}, nil
	}
}

func SlackChannelRenderer(renderer func(ctx context.Context, model any) (SlackContent, error)) ChannelRenderer {
	return func(ctx context.Context, model any) (Content, error) {
		slack, err := renderer(ctx, model)
		if err != nil {
			return Content{}, err
		}
		return Content{Channel: DeliveryChannelSlack, Slack: &slack}, nil
	}
}

type Definition struct {
	Kind              Kind
	SubscriptionType  string
	SupportedChannels []string
	Renderers         map[string]ChannelRenderer
}

func (d Definition) Validate() error {
	if _, err := d.normalized(); err != nil {
		return err
	}
	return nil
}

func (d Definition) SupportsChannel(channel string) bool {
	normalizedChannel, ok := NormalizeDeliveryChannel(channel)
	if !ok {
		return false
	}
	normalized, err := d.normalized()
	if err != nil {
		return false
	}
	for _, supported := range normalized.SupportedChannels {
		if supported == normalizedChannel {
			return true
		}
	}
	return false
}

func (d Definition) normalized() (Definition, error) {
	if strings.TrimSpace(string(d.Kind)) == "" {
		return Definition{}, fmt.Errorf("%w: definition kind is required", ErrInvalidRequest)
	}

	channels, invalid := NormalizeDeliveryChannels(d.SupportedChannels)
	if len(invalid) > 0 {
		return Definition{}, fmt.Errorf("%w: invalid supported channels %v", ErrUnsupportedChannel, invalid)
	}
	if len(channels) == 0 {
		return Definition{}, fmt.Errorf("%w: at least one supported channel is required", ErrInvalidRequest)
	}

	normalized := d
	normalized.Kind = Kind(strings.TrimSpace(string(d.Kind)))
	normalized.SupportedChannels = append([]string(nil), channels...)
	normalized.SubscriptionType = canonicalSubscriptionType(d.SubscriptionType)
	normalized.Renderers = make(map[string]ChannelRenderer, len(d.Renderers))
	for key, renderer := range d.Renderers {
		channel, ok := NormalizeDeliveryChannel(key)
		if !ok {
			return Definition{}, fmt.Errorf("%w: invalid renderer channel %q", ErrUnsupportedChannel, key)
		}
		normalized.Renderers[channel] = renderer
	}

	for _, channel := range normalized.SupportedChannels {
		if normalized.Renderers[channel] == nil {
			return Definition{}, fmt.Errorf("%w: renderer is required for channel %q", ErrInvalidRequest, channel)
		}
	}

	return normalized, nil
}

func canonicalSubscriptionType(subscriptionType string) string {
	trimmed := strings.TrimSpace(subscriptionType)
	if trimmed == "" {
		return ""
	}
	if canonical, ok := NormalizeNotificationType(trimmed); ok {
		return canonical
	}
	return trimmed
}
