package notification

import (
	"context"
	"fmt"
	"strings"
)

func renderContent(ctx context.Context, definition Definition, channel string, model any, defaultEmailFrom string) (Content, error) {
	normalizedChannel, ok := NormalizeDeliveryChannel(channel)
	if !ok {
		return Content{}, fmt.Errorf("%w: invalid channel %q", ErrUnsupportedChannel, channel)
	}

	renderer := definition.Renderers[normalizedChannel]
	if renderer == nil {
		return Content{}, fmt.Errorf("%w: renderer missing for channel %q and kind %q", ErrInvalidContent, channel, definition.Kind)
	}

	content, err := renderer(ctx, model)
	if err != nil {
		return Content{}, err
	}

	if strings.TrimSpace(content.Channel) == "" {
		content.Channel = normalizedChannel
	}
	if content.Channel != normalizedChannel {
		return Content{}, fmt.Errorf("%w: renderer returned channel %q for requested channel %q", ErrInvalidContent, content.Channel, normalizedChannel)
	}

	if normalizedChannel == DeliveryChannelEmail && content.Email != nil {
		if strings.TrimSpace(content.Email.From) == "" {
			content.Email.From = strings.TrimSpace(defaultEmailFrom)
		}
		if strings.TrimSpace(content.Email.From) == "" {
			return Content{}, ErrMissingEmailFromAddress
		}
	}
	if err := content.Validate(); err != nil {
		return Content{}, err
	}

	return content, nil
}
