package digest

import (
	"github.com/compliance-framework/api/internal/service/email"
	"github.com/compliance-framework/api/internal/service/notification"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
	slackprovider "github.com/compliance-framework/api/internal/service/notification/providers/slack"
	notificationruntime "github.com/compliance-framework/api/internal/service/notification/runtime"
)

// NewRuntimeProvider builds the digest notification runtime provider using the
// shared notification runtime registration path.
func NewRuntimeProvider(
	emailService *email.Service,
	workerEnqueuerProvider notification.WorkerEnqueuerProvider,
	slackSender slackprovider.Sender,
) notification.RuntimeProvider {
	if workerEnqueuerProvider == nil {
		workerEnqueuerProvider = func() notification.WorkerEnqueuer { return nil }
	}

	return notificationruntime.NewRegisteredRuntimeProvider(notificationruntime.ProviderRegistrations{
		EmailSender: func() emailprovider.Sender { return emailService },
		EmailEnqueuer: func() emailprovider.Enqueuer {
			workerEnqueuer := workerEnqueuerProvider()
			if workerEnqueuer == nil {
				return nil
			}

			enqueuer, ok := workerEnqueuer.(emailprovider.Enqueuer)
			if !ok {
				return nil
			}

			return enqueuer
		},
		EmailContentRenderer: NewEmailTemplateRendererProvider(emailService),
		SlackSender: func() slackprovider.Sender {
			return slackSender
		},
		SlackEnqueuer: func() slackprovider.Enqueuer {
			workerEnqueuer := workerEnqueuerProvider()
			if workerEnqueuer == nil {
				return nil
			}

			enqueuer, ok := workerEnqueuer.(slackprovider.Enqueuer)
			if !ok {
				return nil
			}

			return enqueuer
		},
	})
}
