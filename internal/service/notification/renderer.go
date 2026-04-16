package notification

import (
	"context"
	"fmt"
	"strings"
)

func renderContent(ctx context.Context, definition Definition, channel string, model any) (Content, error) {
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

	if strings.TrimSpace(content.Provider) == "" {
		content.Provider = normalizedChannel
	}
	if content.Provider != normalizedChannel {
		return Content{}, fmt.Errorf("%w: renderer returned provider %q for requested provider %q", ErrInvalidContent, content.Provider, normalizedChannel)
	}

	if err := content.Validate(); err != nil {
		return Content{}, err
	}

	return content, nil
}
