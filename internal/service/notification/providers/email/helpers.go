package email

import (
	"context"
	"strings"

	"github.com/compliance-framework/api/internal/service/notification"
)

const (
	ChannelID       = notification.DeliveryChannelEmail
	AddressKeyEmail = "email"
)

func Renderer(renderer func(ctx context.Context, model any) (Content, error)) notification.ChannelRenderer {
	return notification.ProviderRenderer(ChannelID, func(ctx context.Context, model any) (any, error) {
		return renderer(ctx, model)
	})
}

func Channel(renderer func(ctx context.Context, model any) (Content, error)) notification.RendererBinding {
	return notification.BindRenderer(ChannelID, Renderer(renderer))
}

func TemplateRenderer(renderer func(ctx context.Context, model any) (TemplateContent, error)) notification.ChannelRenderer {
	return notification.ProviderRenderer(ChannelID, func(ctx context.Context, model any) (any, error) {
		return renderer(ctx, model)
	})
}

func TemplateChannel(renderer func(ctx context.Context, model any) (TemplateContent, error)) notification.RendererBinding {
	return notification.BindRenderer(ChannelID, TemplateRenderer(renderer))
}

func Identity(address string) map[string]string {
	trimmedAddress := strings.TrimSpace(address)
	if trimmedAddress == "" {
		return nil
	}

	return map[string]string{AddressKeyEmail: trimmedAddress}
}
