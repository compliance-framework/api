package notification

import (
	"context"
	"fmt"
	"strings"
)

type ChannelRenderer func(ctx context.Context, model any) (Content, error)

type RendererBinding struct {
	Provider string
	Renderer ChannelRenderer
}

func ProviderRenderer(provider string, renderer func(ctx context.Context, model any) (any, error)) ChannelRenderer {
	return func(ctx context.Context, model any) (Content, error) {
		payload, err := renderer(ctx, model)
		if err != nil {
			return Content{}, err
		}
		return Content{Provider: provider, Payload: payload}, nil
	}
}

func BindRenderer(provider string, renderer ChannelRenderer) RendererBinding {
	return RendererBinding{
		Provider: strings.TrimSpace(provider),
		Renderer: renderer,
	}
}

func NewDefinition(kind Kind, subscriptionGate string, bindings ...RendererBinding) Definition {
	supportedChannels := make([]string, 0, len(bindings))
	renderers := make(map[string]ChannelRenderer, len(bindings))

	for _, binding := range bindings {
		provider := strings.TrimSpace(binding.Provider)
		supportedChannels = append(supportedChannels, provider)
		renderers[provider] = binding.Renderer
	}

	return Definition{
		Kind:              kind,
		SubscriptionGate:  subscriptionGate,
		SupportedChannels: supportedChannels,
		Renderers:         renderers,
	}
}

type Definition struct {
	Kind              Kind
	SubscriptionGate  string
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
	normalized.SubscriptionGate = canonicalSubscriptionGate(d.SubscriptionGate)
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

func canonicalSubscriptionGate(subscriptionGate string) string {
	trimmed := strings.TrimSpace(subscriptionGate)
	if trimmed == "" {
		return ""
	}
	if canonical, ok := NormalizeSubscriptionGate(trimmed); ok {
		return canonical
	}
	return trimmed
}
