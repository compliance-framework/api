package runtime

import (
	notification "github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
)

// ProviderRegistrations defines the channel providers used to build
// a notification runtime provider.
type ProviderRegistrations struct {
	EmailSender          emailprovider.SenderProvider
	EmailEnqueuer        emailprovider.EnqueuerProvider
	EmailContentRenderer emailprovider.ContentRendererProvider
	SlackSender          slackprovider.SenderProvider
	SlackEnqueuer        slackprovider.EnqueuerProvider
}

// NewRegisteredRuntimeProvider builds a RuntimeProvider from registered channel providers.
func NewRegisteredRuntimeProvider(reg ProviderRegistrations, opts ...notification.ServiceOption) notification.RuntimeProvider {
	transport := notification.NewDeliveryTransport(
		notification.WithProvider(emailprovider.NewProviderWithTemplateRenderer(
			reg.EmailSender,
			reg.EmailEnqueuer,
			reg.EmailContentRenderer,
		)),
		notification.WithProvider(slackprovider.NewProvider(
			reg.SlackSender,
			reg.SlackEnqueuer,
		)),
	)

	return notification.NewStaticRuntimeProvider(transport, opts...)
}
