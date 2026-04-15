package notification

import (
	"context"
	"fmt"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
)

type WorkerEnqueuer interface {
	IsStarted() bool
	EnqueueNotificationEmail(ctx context.Context, delivery EmailDelivery) error
	EnqueueNotificationSlack(ctx context.Context, delivery SlackDelivery) error
}

type EmailSender interface {
	IsEnabled() bool
	Send(ctx context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error)
}

type SlackSender interface {
	IsEnabled() bool
	SendMessage(ctx context.Context, channel string, message *slacktypes.Message) (*slacktypes.SendResult, error)
}

type WorkerEnqueuerProvider func() WorkerEnqueuer

type EmailSenderProvider func() EmailSender

type SlackSenderProvider func() SlackSender

type ChannelDriver interface {
	Channel() string
	Deliver(ctx context.Context, delivery Delivery) error
}

type DeliveryTransport struct {
	drivers map[string]ChannelDriver
}

type DeliveryTransportOption func(*DeliveryTransport)

func NewDeliveryTransport(opts ...DeliveryTransportOption) *DeliveryTransport {
	transport := &DeliveryTransport{drivers: map[string]ChannelDriver{}}

	for _, opt := range opts {
		if opt != nil {
			opt(transport)
		}
	}

	return transport
}

func WithWorkerEnqueuerProvider(provider WorkerEnqueuerProvider) DeliveryTransportOption {
	emailDriver := &EmailChannelDriver{workerProvider: provider}
	slackDriver := &SlackChannelDriver{workerProvider: provider}

	return func(transport *DeliveryTransport) {
		transport.registerDriver(emailDriver)
		transport.registerDriver(slackDriver)
	}
}

func WithEmailSenderProvider(provider EmailSenderProvider) DeliveryTransportOption {
	driver := &EmailChannelDriver{emailProvider: provider}

	return func(transport *DeliveryTransport) {
		transport.registerDriver(driver)
	}
}

func WithSlackSenderProvider(provider SlackSenderProvider) DeliveryTransportOption {
	driver := &SlackChannelDriver{slackProvider: provider}

	return func(transport *DeliveryTransport) {
		transport.registerDriver(driver)
	}
}

func (t *DeliveryTransport) Enqueue(ctx context.Context, deliveries []Delivery) error {
	for i := range deliveries {
		delivery := deliveries[i]
		if err := delivery.Validate(); err != nil {
			return err
		}

		driver := t.driverFor(delivery.Channel)
		if driver == nil {
			return fmt.Errorf("%w: no driver registered for channel %q", ErrUnsupportedChannel, delivery.Channel)
		}

		if err := driver.Deliver(ctx, delivery); err != nil {
			return fmt.Errorf("deliver channel %q: %w", delivery.Channel, err)
		}
	}

	return nil
}

func (t *DeliveryTransport) driverFor(channel string) ChannelDriver {
	if t == nil {
		return nil
	}
	normalized, ok := NormalizeDeliveryChannel(channel)
	if !ok {
		return nil
	}

	return t.drivers[normalized]
}

func (t *DeliveryTransport) registerDriver(driver ChannelDriver) {
	if t == nil || driver == nil {
		return
	}
	channel, ok := NormalizeDeliveryChannel(driver.Channel())
	if !ok {
		return
	}

	existing := t.drivers[channel]
	if existing == nil {
		t.drivers[channel] = driver
		return
	}

	switch current := existing.(type) {
	case *EmailChannelDriver:
		incoming, ok := driver.(*EmailChannelDriver)
		if !ok {
			t.drivers[channel] = driver
			return
		}
		if incoming.workerProvider != nil {
			current.workerProvider = incoming.workerProvider
		}
		if incoming.emailProvider != nil {
			current.emailProvider = incoming.emailProvider
		}
	case *SlackChannelDriver:
		incoming, ok := driver.(*SlackChannelDriver)
		if !ok {
			t.drivers[channel] = driver
			return
		}
		if incoming.workerProvider != nil {
			current.workerProvider = incoming.workerProvider
		}
		if incoming.slackProvider != nil {
			current.slackProvider = incoming.slackProvider
		}
	default:
		t.drivers[channel] = driver
	}
}

type EmailChannelDriver struct {
	workerProvider WorkerEnqueuerProvider
	emailProvider  EmailSenderProvider
}

func (d *EmailChannelDriver) Channel() string { return DeliveryChannelEmail }

func (d *EmailChannelDriver) Deliver(ctx context.Context, delivery Delivery) error {
	if delivery.Content.Email == nil {
		return fmt.Errorf("missing email content")
	}

	providerDelivery := EmailDelivery{
		To:       delivery.Target.Address,
		Content:  delivery.Content.Email.Clone(),
		Metadata: delivery.Metadata,
	}

	if worker := d.worker(); worker != nil && worker.IsStarted() {
		if err := worker.EnqueueNotificationEmail(ctx, providerDelivery); err != nil {
			return fmt.Errorf("enqueue email delivery: %w", err)
		}
		return nil
	}

	sender := d.email()
	if sender == nil || !sender.IsEnabled() {
		return fmt.Errorf("email service is not enabled")
	}

	message := &emailtypes.Message{
		From:        providerDelivery.Content.From,
		To:          []string{providerDelivery.To},
		Subject:     providerDelivery.Content.Subject,
		HTMLBody:    providerDelivery.Content.HTMLBody,
		TextBody:    providerDelivery.Content.TextBody,
		Attachments: providerDelivery.Content.Attachments,
		Headers:     providerDelivery.Content.Headers,
	}

	result, err := sender.Send(ctx, message)
	if err != nil {
		return fmt.Errorf("send email delivery: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("email delivery send failed: %s", result.Error)
	}

	return nil
}

func (d *EmailChannelDriver) worker() WorkerEnqueuer {
	if d == nil || d.workerProvider == nil {
		return nil
	}

	return d.workerProvider()
}

func (d *EmailChannelDriver) email() EmailSender {
	if d == nil || d.emailProvider == nil {
		return nil
	}

	return d.emailProvider()
}

type SlackChannelDriver struct {
	workerProvider WorkerEnqueuerProvider
	slackProvider  SlackSenderProvider
}

func (d *SlackChannelDriver) Channel() string { return DeliveryChannelSlack }

func (d *SlackChannelDriver) Deliver(ctx context.Context, delivery Delivery) error {
	if delivery.Content.Slack == nil {
		return fmt.Errorf("missing slack content")
	}

	targetType, ok := delivery.Target.Attribute("target_type")
	if !ok {
		return fmt.Errorf("missing slack target_type")
	}

	providerDelivery := SlackDelivery{
		Channel:    delivery.Target.Address,
		TargetType: targetType,
		Content:    delivery.Content.Slack.Clone(),
		Metadata:   delivery.Metadata,
	}

	if worker := d.worker(); worker != nil && worker.IsStarted() {
		if err := worker.EnqueueNotificationSlack(ctx, providerDelivery); err != nil {
			return fmt.Errorf("enqueue slack delivery: %w", err)
		}
		return nil
	}

	sender := d.slack()
	if sender == nil || !sender.IsEnabled() {
		return nil
	}

	message := &slacktypes.Message{
		Text:   providerDelivery.Content.Text,
		Blocks: append([]slack.Block(nil), providerDelivery.Content.Blocks...),
	}

	result, err := sender.SendMessage(ctx, providerDelivery.Channel, message)
	if err != nil {
		return fmt.Errorf("send slack delivery: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("slack delivery send failed: %s", result.Error)
	}

	return nil
}

func (d *SlackChannelDriver) worker() WorkerEnqueuer {
	if d == nil || d.workerProvider == nil {
		return nil
	}

	return d.workerProvider()
}

func (d *SlackChannelDriver) slack() SlackSender {
	if d == nil || d.slackProvider == nil {
		return nil
	}

	return d.slackProvider()
}
