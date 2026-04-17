package slack

import (
	"context"
	"strings"

	"github.com/compliance-framework/api/internal/service/notification"
)

const (
	ChannelID            = notification.DeliveryChannelSlack
	AddressKeyChannel    = "channel"
	AddressKeyTargetType = "target_type"
)

func Renderer(renderer func(ctx context.Context, model any) (Content, error)) notification.ChannelRenderer {
	return notification.ProviderRenderer(ChannelID, func(ctx context.Context, model any) (any, error) {
		return renderer(ctx, model)
	})
}

func Channel(renderer func(ctx context.Context, model any) (Content, error)) notification.RendererBinding {
	return notification.BindRenderer(ChannelID, Renderer(renderer))
}

func DirectMessageIdentity(channel string) map[string]string {
	trimmedChannel := strings.TrimSpace(channel)
	if trimmedChannel == "" {
		return nil
	}

	return map[string]string{
		AddressKeyChannel:    trimmedChannel,
		AddressKeyTargetType: TargetTypeDirectMessage,
	}
}
