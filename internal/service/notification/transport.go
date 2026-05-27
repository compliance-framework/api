package notification

import (
	"context"
	"fmt"
	"sort"
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

type ProviderMetadata struct {
	ProviderType string
	DisplayName  string
	Description  string
	Enabled      bool
	Error        string
	Metadata     map[string]string
}

type ProviderMetadataProvider interface {
	ProviderMetadata() ProviderMetadata
}

type ProviderCatalog interface {
	ProviderIDs() []string
	Providers() []ProviderMetadata
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

func (t *DeliveryTransport) ProviderIDs() []string {
	if t == nil {
		return nil
	}

	providerIDs := make([]string, 0, len(t.providers))
	for providerID := range t.providers {
		providerIDs = append(providerIDs, providerID)
	}
	sort.Strings(providerIDs)

	return providerIDs
}

func (t *DeliveryTransport) Providers() []ProviderMetadata {
	if t == nil {
		return nil
	}

	providerIDs := t.ProviderIDs()
	providers := make([]ProviderMetadata, 0, len(providerIDs))
	for _, providerID := range providerIDs {
		metadata := ProviderMetadata{
			ProviderType: providerID,
			DisplayName:  providerID,
		}

		if providerWithMetadata, ok := t.providers[providerID].(ProviderMetadataProvider); ok {
			metadata = providerWithMetadata.ProviderMetadata()
		}

		if canonicalProviderType, ok := NormalizeDeliveryChannel(metadata.ProviderType); ok {
			metadata.ProviderType = canonicalProviderType
		} else {
			metadata.ProviderType = providerID
		}
		if metadata.DisplayName == "" {
			metadata.DisplayName = metadata.ProviderType
		}
		if len(metadata.Metadata) > 0 {
			cloned := make(map[string]string, len(metadata.Metadata))
			for key, value := range metadata.Metadata {
				cloned[key] = value
			}
			metadata.Metadata = cloned
		}

		providers = append(providers, metadata)
	}

	return providers
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
