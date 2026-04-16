package notification

import (
	"context"
	"fmt"
	"strings"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
)

type WorkerEnqueuer interface {
	IsStarted() bool
	EnqueueNotificationEmail(ctx context.Context, delivery EmailDelivery) error
}

type EmailSender interface {
	IsEnabled() bool
	Send(ctx context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error)
}

type WorkerEnqueuerProvider func() WorkerEnqueuer

type EmailSenderProvider func() EmailSender

type Provider interface {
	ID() string
	ResolveUserTarget(user User) (Target, bool, error)
	ValidateTarget(target Target) error
	Deliver(ctx context.Context, delivery Delivery) error
}

type ProviderLookup interface {
	Provider(providerID string) (Provider, bool)
}

type DeliveryTransport struct {
	providers map[string]Provider
}

type DeliveryTransportOption func(*DeliveryTransport)

func NewDeliveryTransport(opts ...DeliveryTransportOption) *DeliveryTransport {
	transport := &DeliveryTransport{providers: map[string]Provider{}}

	for _, opt := range opts {
		if opt != nil {
			opt(transport)
		}
	}

	return transport
}

func WithProvider(provider Provider) DeliveryTransportOption {
	return func(transport *DeliveryTransport) {
		transport.registerProvider(provider)
	}
}

func WithProviders(providers ...Provider) DeliveryTransportOption {
	return func(transport *DeliveryTransport) {
		for i := range providers {
			transport.registerProvider(providers[i])
		}
	}
}

func WithWorkerEnqueuerProvider(provider WorkerEnqueuerProvider) DeliveryTransportOption {
	emailProvider := &EmailProvider{workerProvider: provider}

	return func(transport *DeliveryTransport) {
		transport.registerProvider(emailProvider)
	}
}

func WithEmailSenderProvider(provider EmailSenderProvider) DeliveryTransportOption {
	driver := &EmailProvider{emailProvider: provider}

	return func(transport *DeliveryTransport) {
		transport.registerProvider(driver)
	}
}

func (t *DeliveryTransport) Enqueue(ctx context.Context, deliveries []Delivery) error {
	for i := range deliveries {
		delivery := deliveries[i]
		if err := delivery.Validate(); err != nil {
			return err
		}

		provider, ok := t.Provider(delivery.Provider)
		if !ok {
			return fmt.Errorf("%w: no provider registered for id %q", ErrUnsupportedChannel, delivery.Provider)
		}
		if err := provider.ValidateTarget(delivery.Target); err != nil {
			return err
		}

		if err := provider.Deliver(ctx, delivery); err != nil {
			return fmt.Errorf("deliver provider %q: %w", delivery.Provider, err)
		}
	}

	return nil
}

func (t *DeliveryTransport) Provider(providerID string) (Provider, bool) {
	if t == nil {
		return nil, false
	}
	canonical, ok := NormalizeDeliveryChannel(providerID)
	if !ok {
		return nil, false
	}

	provider, exists := t.providers[canonical]
	return provider, exists
}

func (t *DeliveryTransport) registerProvider(provider Provider) {
	if t == nil || provider == nil {
		return
	}
	providerID, ok := NormalizeDeliveryChannel(provider.ID())
	if !ok {
		return
	}

	existing := t.providers[providerID]
	if existing == nil {
		t.providers[providerID] = provider
		return
	}

	switch current := existing.(type) {
	case *EmailProvider:
		incoming, ok := provider.(*EmailProvider)
		if !ok {
			t.providers[providerID] = provider
			return
		}
		if incoming.workerProvider != nil {
			current.workerProvider = incoming.workerProvider
		}
		if incoming.emailProvider != nil {
			current.emailProvider = incoming.emailProvider
		}
	default:
		t.providers[providerID] = provider
	}
}

type EmailProvider struct {
	workerProvider WorkerEnqueuerProvider
	emailProvider  EmailSenderProvider
}

func (p *EmailProvider) ID() string { return DeliveryChannelEmail }

func (p *EmailProvider) ResolveUserTarget(user User) (Target, bool, error) {
	if identity, ok := userIdentity(user, DeliveryChannelEmail); ok {
		return Target{
			Provider: DeliveryChannelEmail,
			UserID:   user.ID,
			Address:  identity,
		}, true, nil
	}

	return Target{}, false, nil
}

func (p *EmailProvider) ValidateTarget(target Target) error {
	email := strings.TrimSpace(target.Address["email"])
	if email == "" {
		return fmt.Errorf("%w: email provider requires email address", ErrInvalidTarget)
	}

	return nil
}

func (p *EmailProvider) Deliver(ctx context.Context, delivery Delivery) error {
	emailContent, err := extractEmailContent(delivery.Content.Payload)
	if err != nil {
		return err
	}

	to := strings.TrimSpace(delivery.Target.Address["email"])
	providerDelivery := EmailDelivery{
		To:       to,
		Content:  emailContent,
		Metadata: delivery.Metadata,
	}

	if worker := p.worker(); worker != nil && worker.IsStarted() {
		if err := worker.EnqueueNotificationEmail(ctx, providerDelivery); err != nil {
			return fmt.Errorf("enqueue email delivery: %w", err)
		}
		return nil
	}

	sender := p.email()
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

func (p *EmailProvider) worker() WorkerEnqueuer {
	if p == nil || p.workerProvider == nil {
		return nil
	}

	return p.workerProvider()
}

func (p *EmailProvider) email() EmailSender {
	if p == nil || p.emailProvider == nil {
		return nil
	}

	return p.emailProvider()
}

type NotImplementedProvider struct {
	id string
}

func NewNotImplementedProvider(id string) *NotImplementedProvider {
	return &NotImplementedProvider{id: strings.TrimSpace(id)}
}

func (p *NotImplementedProvider) ID() string { return p.id }

func (p *NotImplementedProvider) ResolveUserTarget(_ User) (Target, bool, error) {
	return Target{}, false, nil
}

func (p *NotImplementedProvider) ValidateTarget(_ Target) error {
	return nil
}

func (p *NotImplementedProvider) Deliver(_ context.Context, _ Delivery) error {
	return fmt.Errorf("provider %q is not implemented", p.id)
}

func userIdentity(user User, provider string) (map[string]string, bool) {
	if len(user.Identities) > 0 {
		if identity, ok := user.Identities[provider]; ok && len(identity) > 0 {
			cloned := make(map[string]string, len(identity))
			for key, value := range identity {
				cloned[key] = strings.TrimSpace(value)
			}
			return cloned, true
		}
	}

	switch provider {
	case DeliveryChannelEmail:
		email := strings.TrimSpace(user.Email)
		if email == "" {
			return nil, false
		}
		return map[string]string{"email": email}, true
	default:
		return nil, false
	}
}

func extractEmailContent(payload any) (EmailContent, error) {
	switch typed := payload.(type) {
	case EmailContent:
		return typed.Clone(), nil
	case *EmailContent:
		if typed == nil {
			return EmailContent{}, fmt.Errorf("missing email content")
		}
		return typed.Clone(), nil
	default:
		return EmailContent{}, fmt.Errorf("email provider expects EmailContent payload, got %T", payload)
	}
}
