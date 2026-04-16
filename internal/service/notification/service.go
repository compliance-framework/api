package notification

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type ServiceOption func(*Service)

type Service struct {
	transport        Transport
	registry         *Registry
	resolver         *Resolver
	defaultEmailFrom string
}

type preparedDeliveries struct {
	deliveries []Delivery
}

func NewService(transport Transport, registry *Registry, resolver *Resolver, opts ...ServiceOption) *Service {
	service := &Service{
		transport: transport,
		registry:  registry,
		resolver:  resolver,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(service)
		}
	}

	return service
}

func WithDefaultEmailFrom(address string) ServiceOption {
	return func(service *Service) {
		service.defaultEmailFrom = strings.TrimSpace(address)
	}
}

func (s *Service) Resolve(ctx context.Context, request Request) ([]Target, Definition, error) {
	if s == nil || s.registry == nil {
		return nil, Definition{}, ErrRegistryNotConfigured
	}
	if s.resolver == nil {
		return nil, Definition{}, ErrResolverNotConfigured
	}

	definition, ok := s.registry.Definition(request.Kind)
	if !ok {
		return nil, Definition{}, fmt.Errorf("%w: kind %q", ErrDefinitionNotFound, request.Kind)
	}

	targets, err := s.resolver.Resolve(ctx, request, definition)
	if err != nil {
		return nil, Definition{}, err
	}

	return targets, definition, nil
}

func (s *Service) Dispatch(ctx context.Context, request Request) error {
	if s == nil || s.transport == nil {
		return ErrTransportNotConfigured
	}

	deliveries, err := s.buildDispatchDeliveries(ctx, request)
	if err != nil {
		return err
	}
	return s.enqueuePreparedDeliveries(ctx, deliveries)
}

func (s *Service) DispatchFanout(ctx context.Context, request FanoutRequest) error {
	if s == nil || s.transport == nil {
		return ErrTransportNotConfigured
	}
	if err := request.Validate(); err != nil {
		return err
	}

	deliveries := preparedDeliveries{}

	for i := range request.Requests {
		prepared, err := s.buildDispatchDeliveries(ctx, request.Requests[i])
		if err != nil {
			return err
		}
		deliveries.appendGroup(prepared)
	}

	for i := range request.SubscribedUsers {
		prepared, err := s.buildSubscribedUsersDeliveries(ctx, request.SubscribedUsers[i])
		if err != nil {
			return err
		}
		deliveries.appendGroup(prepared)
	}

	return s.enqueuePreparedDeliveries(ctx, deliveries)
}

func (s *Service) buildDispatchDeliveries(ctx context.Context, request Request) (preparedDeliveries, error) {
	targets, definition, err := s.Resolve(ctx, request)
	if err != nil {
		return preparedDeliveries{}, err
	}
	if len(targets) == 0 {
		return preparedDeliveries{}, nil
	}

	return s.renderDeliveries(ctx, request, definition, targets)
}

func (s *Service) buildSubscribedUsersDeliveries(ctx context.Context, request SubscribedUsersRequest) (preparedDeliveries, error) {
	if s == nil || s.registry == nil {
		return preparedDeliveries{}, ErrRegistryNotConfigured
	}
	if s.resolver == nil {
		return preparedDeliveries{}, ErrResolverNotConfigured
	}

	definition, ok := s.registry.Definition(request.Kind)
	if !ok {
		return preparedDeliveries{}, fmt.Errorf("%w: kind %q", ErrDefinitionNotFound, request.Kind)
	}

	users, err := s.resolver.ListSubscribedUsers(ctx, definition)
	if err != nil {
		return preparedDeliveries{}, err
	}

	deliveries := preparedDeliveries{}
	for i := range users {
		user := users[i]

		targets, err := s.resolver.ResolveUser(user, request.Options, definition)
		if err != nil {
			return preparedDeliveries{}, fmt.Errorf("resolve subscribed user %s: %w", user.ID, err)
		}
		if len(targets) == 0 {
			continue
		}

		model := request.Model
		if request.BuildModel != nil {
			model, err = request.BuildModel(ctx, user)
			if err != nil {
				return preparedDeliveries{}, fmt.Errorf("build model for user %s: %w", user.ID, err)
			}
		}

		prepared, err := s.renderDeliveries(ctx, Request{
			Kind:    request.Kind,
			Model:   model,
			Options: request.Options,
		}, definition, targets)
		if err != nil {
			return preparedDeliveries{}, err
		}
		deliveries.appendGroup(prepared)
	}

	return deliveries, nil
}

func (s *Service) renderDeliveries(ctx context.Context, request Request, definition Definition, targets []Target) (preparedDeliveries, error) {
	contentByProvider := make(map[string]Content)
	deliveries := preparedDeliveries{}

	for _, target := range targets {
		provider, ok := NormalizeDeliveryChannel(target.Provider)
		if !ok {
			return preparedDeliveries{}, fmt.Errorf("%w: target provider %q", ErrUnsupportedChannel, target.Provider)
		}

		content, exists := contentByProvider[provider]
		if !exists {
			rendered, err := renderContent(ctx, definition, provider, request.Model, s.defaultEmailFrom)
			if err != nil {
				return preparedDeliveries{}, fmt.Errorf("render %s for kind %q: %w", provider, request.Kind, err)
			}
			content = rendered
			contentByProvider[provider] = rendered
		}

		metadata := TransportMetadata{
			NotificationKind: request.Kind,
			Provider:         provider,
			Channel:          provider,
			RecipientUserID:  strings.TrimSpace(target.UserID),
			Target:           stringifyTargetAddress(target.Address),
			CorrelationID:    strings.TrimSpace(request.Options.CorrelationID),
			SourceJobKind:    strings.TrimSpace(request.Options.SourceJobKind),
			SourceJobID:      strings.TrimSpace(request.Options.SourceJobID),
		}

		delivery := Delivery{
			Provider: provider,
			Target:   target,
			Content:  content.Clone(),
			Metadata: metadata,
		}
		if err := delivery.Validate(); err != nil {
			return preparedDeliveries{}, err
		}

		deliveries.append(delivery)
	}

	return deliveries, nil
}

func stringifyTargetAddress(address map[string]string) string {
	if len(address) == 0 {
		return ""
	}

	if v := strings.TrimSpace(address["email"]); v != "" {
		return v
	}
	if v := strings.TrimSpace(address["channel"]); v != "" {
		return v
	}
	if v := strings.TrimSpace(address["id"]); v != "" {
		return v
	}

	keys := make([]string, 0, len(address))
	for key := range address {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strings.TrimSpace(address[key]))
	}

	return strings.Join(parts, ",")
}

func (s *Service) enqueuePreparedDeliveries(ctx context.Context, deliveries preparedDeliveries) error {
	if len(deliveries.deliveries) == 0 {
		return nil
	}

	if err := s.transport.Enqueue(ctx, deliveries.deliveries); err != nil {
		return fmt.Errorf("enqueue deliveries: %w", err)
	}

	return nil
}

func (d *preparedDeliveries) append(other Delivery) {
	d.deliveries = append(d.deliveries, other)
}

func (d *preparedDeliveries) appendGroup(other preparedDeliveries) {
	for i := range other.deliveries {
		d.append(other.deliveries[i])
	}
}
