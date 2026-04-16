package notification

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

var (
	ErrInvalidRequest                = errors.New("invalid notification request")
	ErrInvalidAudience               = errors.New("invalid notification audience")
	ErrInvalidTarget                 = errors.New("invalid notification target")
	ErrInvalidContent                = errors.New("invalid notification content")
	ErrUnsupportedChannel            = errors.New("unsupported notification channel")
	ErrDefinitionNotFound            = errors.New("notification definition not found")
	ErrResolverNotConfigured         = errors.New("notification resolver is not configured")
	ErrRegistryNotConfigured         = errors.New("notification registry is not configured")
	ErrTransportNotConfigured        = errors.New("notification transport is not configured")
	ErrConfiguredDestinationNotFound = errors.New("configured notification destination not found")
	ErrMissingSubscriptionType       = errors.New("notification definition requires a subscription type for user audiences")
)

type Kind string

type Request struct {
	Kind      Kind
	Audiences []Audience
	Model     any
	Options   DispatchOptions
}

type UserModelBuilder func(ctx context.Context, user User) (any, error)

type SubscribedUsersRequest struct {
	Kind       Kind
	Model      any
	BuildModel UserModelBuilder
	Options    DispatchOptions
}

type FanoutRequest struct {
	Requests        []Request
	SubscribedUsers []SubscribedUsersRequest
}

type DispatchOptions struct {
	RequestedChannel string
	CorrelationID    string
	SourceJobKind    string
	SourceJobID      string
}

type Audience struct {
	User                  *UserAudience
	Direct                *DirectAudience
	ConfiguredDestination *ConfiguredDestinationAudience
}

type UserAudience struct {
	UserID string
}

type DirectAudience struct {
	Provider string
	Address  map[string]string
}

type ConfiguredDestinationAudience struct {
	Key string
}

func (r Request) Validate() error {
	if strings.TrimSpace(string(r.Kind)) == "" {
		return fmt.Errorf("%w: kind is required", ErrInvalidRequest)
	}
	if len(r.Audiences) == 0 {
		return fmt.Errorf("%w: at least one audience is required", ErrInvalidRequest)
	}
	for i := range r.Audiences {
		if err := r.Audiences[i].Validate(); err != nil {
			return fmt.Errorf("%w at index %d: %w", ErrInvalidRequest, i, err)
		}
	}
	if _, ok := normalizeRequestedChannel(r.Options.RequestedChannel); !ok {
		return fmt.Errorf("%w: requested channel %q", ErrInvalidRequest, r.Options.RequestedChannel)
	}
	if err := r.Options.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return nil
}

func (a Audience) Validate() error {
	modeCount := 0
	if a.User != nil {
		modeCount++
	}
	if a.Direct != nil {
		modeCount++
	}
	if a.ConfiguredDestination != nil {
		modeCount++
	}
	if modeCount != 1 {
		return fmt.Errorf("%w: exactly one audience mode must be set", ErrInvalidAudience)
	}

	switch {
	case a.User != nil:
		if strings.TrimSpace(a.User.UserID) == "" {
			return fmt.Errorf("%w: user audience requires user id", ErrInvalidAudience)
		}
	case a.Direct != nil:
		if _, ok := NormalizeDeliveryChannel(a.Direct.Provider); !ok {
			return fmt.Errorf("%w: direct audience requires a supported provider", ErrInvalidAudience)
		}
		if len(a.Direct.Address) == 0 {
			return fmt.Errorf("%w: direct audience requires address attributes", ErrInvalidAudience)
		}
	case a.ConfiguredDestination != nil:
		if strings.TrimSpace(a.ConfiguredDestination.Key) == "" {
			return fmt.Errorf("%w: configured destination audience requires key", ErrInvalidAudience)
		}
	}

	return nil
}

func (r SubscribedUsersRequest) Validate() error {
	if strings.TrimSpace(string(r.Kind)) == "" {
		return fmt.Errorf("%w: kind is required", ErrInvalidRequest)
	}
	if _, ok := normalizeRequestedChannel(r.Options.RequestedChannel); !ok {
		return fmt.Errorf("%w: requested channel %q", ErrInvalidRequest, r.Options.RequestedChannel)
	}
	if err := r.Options.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if r.BuildModel == nil && r.Model == nil {
		return fmt.Errorf("%w: subscribed users request requires a model or model builder", ErrInvalidRequest)
	}
	if r.BuildModel != nil && r.Model != nil {
		return fmt.Errorf("%w: subscribed users request accepts either model or model builder, not both", ErrInvalidRequest)
	}

	return nil
}

func (o DispatchOptions) Validate() error {
	return nil
}

func (r FanoutRequest) Validate() error {
	if len(r.Requests) == 0 && len(r.SubscribedUsers) == 0 {
		return fmt.Errorf("%w: fanout request requires at least one dispatch item", ErrInvalidRequest)
	}

	for i := range r.Requests {
		if err := r.Requests[i].Validate(); err != nil {
			return fmt.Errorf("%w in request %d: %w", ErrInvalidRequest, i, err)
		}
	}
	for i := range r.SubscribedUsers {
		if err := r.SubscribedUsers[i].Validate(); err != nil {
			return fmt.Errorf("%w in subscribed users request %d: %w", ErrInvalidRequest, i, err)
		}
	}

	return nil
}

type Target struct {
	Provider string
	UserID   string
	Address  map[string]string
}

func (t Target) Validate() error {
	provider, ok := NormalizeDeliveryChannel(t.Provider)
	if !ok {
		return fmt.Errorf("%w: provider %q", ErrInvalidTarget, t.Provider)
	}

	if len(t.Address) == 0 {
		return fmt.Errorf("%w: target requires address attributes", ErrInvalidTarget)
	}

	for key, value := range t.Address {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: target address keys and values are required for provider %q", ErrInvalidTarget, provider)
		}
	}

	return nil
}

func (t Target) Attribute(key string) (string, bool) {
	if len(t.Address) == 0 {
		return "", false
	}

	value := strings.TrimSpace(t.Address[key])
	if value == "" {
		return "", false
	}

	return value, true
}

func (t Target) dedupKey() string {
	if len(t.Address) == 0 {
		return t.Provider + ":"
	}

	keys := make([]string, 0, len(t.Address))
	for key := range t.Address {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strings.TrimSpace(t.Address[key]))
	}

	return t.Provider + ":" + strings.Join(parts, "|")
}

type Content struct {
	Provider string
	Payload  any
}

func (c Content) Validate() error {
	provider, ok := NormalizeDeliveryChannel(c.Provider)
	if !ok {
		return fmt.Errorf("%w: content provider %q", ErrInvalidContent, c.Provider)
	}
	if isNilPayload(c.Payload) {
		return fmt.Errorf("%w: content payload is required for provider %q", ErrInvalidContent, provider)
	}

	if validator, ok := c.Payload.(interface{ Validate() error }); ok {
		if err := validator.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c Content) Clone() Content {
	cloned := Content{Provider: c.Provider}

	if payload, ok := c.Payload.(interface{ ClonePayload() any }); ok && !isNilPayload(c.Payload) {
		cloned.Payload = payload.ClonePayload()
		return cloned
	}

	cloned.Payload = c.Payload

	return cloned
}

type Delivery struct {
	Provider string
	Target   Target
	Content  Content
	Metadata TransportMetadata
}

func (d Delivery) Validate() error {
	provider, ok := NormalizeDeliveryChannel(d.Provider)
	if !ok {
		return fmt.Errorf("%w: delivery provider %q", ErrInvalidTarget, d.Provider)
	}
	if err := d.Target.Validate(); err != nil {
		return err
	}
	if d.Target.Provider != provider {
		return fmt.Errorf("%w: target provider %q does not match delivery provider %q", ErrInvalidTarget, d.Target.Provider, d.Provider)
	}
	if err := d.Content.Validate(); err != nil {
		return err
	}
	if d.Content.Provider != provider {
		return fmt.Errorf("%w: content provider %q does not match delivery provider %q", ErrInvalidContent, d.Content.Provider, d.Provider)
	}

	return nil
}

type TransportMetadata struct {
	NotificationKind Kind
	Provider         string
	Channel          string
	RecipientUserID  string
	Target           string
	CorrelationID    string
	SourceJobKind    string
	SourceJobID      string
}

type Transport interface {
	Enqueue(ctx context.Context, deliveries []Delivery) error
}

type ConfiguredDestination struct {
	Provider string
	Address  map[string]string
}

func (d ConfiguredDestination) Validate() error {
	return Target{
		Provider: d.Provider,
		Address:  d.Address,
	}.Validate()
}

func isNilPayload(payload any) bool {
	if payload == nil {
		return true
	}

	value := reflect.ValueOf(payload)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
