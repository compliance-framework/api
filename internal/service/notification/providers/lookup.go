package providers

import (
	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
)

type LookupOption func(*lookupOptions)

type lookupOptions struct {
	config *config.Config
}

func WithConfig(cfg *config.Config) LookupOption {
	return func(options *lookupOptions) {
		if options == nil {
			return
		}
		options.config = cfg
	}
}

func NewLookup(opts ...LookupOption) notification.ProviderLookup {
	options := lookupOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}

	return notification.NewDeliveryTransport(
		notification.WithProvider(emailprovider.NewCatalogProvider(options.config)),
		notification.WithProvider(slackprovider.NewCatalogProvider(options.config)),
	)
}
