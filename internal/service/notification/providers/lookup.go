package providers

import (
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
)

func NewLookup() notification.ProviderLookup {
	return notification.NewDeliveryTransport(
		notification.WithProvider(emailprovider.NewProvider(nil, nil)),
		notification.WithProvider(slackprovider.NewProvider(nil, nil)),
	)
}
