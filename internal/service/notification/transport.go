package notification

import (
	"context"
	"fmt"
)

type WorkerEnqueuer interface {
	IsStarted() bool
}

type WorkerEnqueuerProvider func() WorkerEnqueuer

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

	t.providers[providerID] = provider
}

type NotImplementedProvider struct {
	id string
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
