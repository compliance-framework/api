package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/slack-go/slack"
)

const (
	ConfiguredDestinationSlackDigestChannel = "slack.digest_channel"
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
	ErrMissingEmailFromAddress       = errors.New("notification email content requires a from address")
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
	DirectEmail           *DirectEmailAudience
	DirectSlack           *DirectSlackAudience
	ConfiguredDestination *ConfiguredDestinationAudience
}

type UserAudience struct {
	UserID string
}

type DirectEmailAudience struct {
	Email string
}

type DirectSlackAudience struct {
	Channel    string
	TargetType string
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
	if a.DirectEmail != nil {
		modeCount++
	}
	if a.DirectSlack != nil {
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
	case a.DirectEmail != nil:
		if strings.TrimSpace(a.DirectEmail.Email) == "" {
			return fmt.Errorf("%w: direct email audience requires email", ErrInvalidAudience)
		}
	case a.DirectSlack != nil:
		if strings.TrimSpace(a.DirectSlack.Channel) == "" {
			return fmt.Errorf("%w: direct slack audience requires channel", ErrInvalidAudience)
		}
		if targetType := strings.TrimSpace(a.DirectSlack.TargetType); targetType != "" {
			if _, ok := NormalizeSlackTarget(targetType); !ok {
				return fmt.Errorf("%w: direct slack audience requires a supported target type", ErrInvalidAudience)
			}
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
	Channel    string
	UserID     string
	Address    string
	Attributes map[string]string
}

func (t Target) Validate() error {
	channel, ok := NormalizeDeliveryChannel(t.Channel)
	if !ok {
		return fmt.Errorf("%w: channel %q", ErrInvalidTarget, t.Channel)
	}

	address := strings.TrimSpace(t.Address)
	if address == "" {
		return fmt.Errorf("%w: target requires address", ErrInvalidTarget)
	}

	switch channel {
	case DeliveryChannelEmail:
	case DeliveryChannelSlack:
		targetType, ok := t.Attribute("target_type")
		if !ok {
			return fmt.Errorf("%w: slack target requires target_type attribute", ErrInvalidTarget)
		}
		if _, ok := NormalizeSlackTarget(targetType); !ok {
			return fmt.Errorf("%w: slack target requires a supported target type", ErrInvalidTarget)
		}
	}

	return nil
}

func (t Target) Attribute(key string) (string, bool) {
	if len(t.Attributes) == 0 {
		return "", false
	}

	value := strings.TrimSpace(t.Attributes[key])
	if value == "" {
		return "", false
	}

	return value, true
}

func (t Target) dedupKey() string {
	return t.Channel + ":" + strings.TrimSpace(t.Address)
}

type EmailContent struct {
	From        string
	Subject     string
	HTMLBody    string
	TextBody    string
	Attachments []emailtypes.Attachment
	Headers     map[string]string
}

func (c EmailContent) Validate() error {
	if strings.TrimSpace(c.Subject) == "" {
		return fmt.Errorf("%w: email content requires subject", ErrInvalidContent)
	}
	if strings.TrimSpace(c.HTMLBody) == "" && strings.TrimSpace(c.TextBody) == "" {
		return fmt.Errorf("%w: email content requires html or text body", ErrInvalidContent)
	}
	return nil
}

func (c EmailContent) Clone() EmailContent {
	cloned := c
	if len(c.Attachments) > 0 {
		cloned.Attachments = append([]emailtypes.Attachment(nil), c.Attachments...)
	}
	if len(c.Headers) > 0 {
		cloned.Headers = make(map[string]string, len(c.Headers))
		for key, value := range c.Headers {
			cloned.Headers[key] = value
		}
	}
	return cloned
}

type SlackContent struct {
	Text   string
	Blocks []slack.Block
}

func (c SlackContent) Validate() error {
	if strings.TrimSpace(c.Text) == "" && len(c.Blocks) == 0 {
		return fmt.Errorf("%w: slack content requires text or blocks", ErrInvalidContent)
	}
	return nil
}

func (c SlackContent) Clone() SlackContent {
	cloned := c
	if len(c.Blocks) > 0 {
		cloned.Blocks = append([]slack.Block(nil), c.Blocks...)
	}
	return cloned
}

type EmailDelivery struct {
	To       string
	Content  EmailContent
	Metadata TransportMetadata
}

func (d EmailDelivery) Validate() error {
	if strings.TrimSpace(d.To) == "" {
		return fmt.Errorf("%w: email delivery requires recipient", ErrInvalidTarget)
	}
	if strings.TrimSpace(d.Content.From) == "" {
		return ErrMissingEmailFromAddress
	}
	return d.Content.Validate()
}

func (d EmailDelivery) dedupKey() string {
	return ""
}

type SlackDelivery struct {
	Channel    string
	TargetType string
	Content    SlackContent
	Metadata   TransportMetadata
}

func (d SlackDelivery) Validate() error {
	if strings.TrimSpace(d.Channel) == "" {
		return fmt.Errorf("%w: slack delivery requires channel", ErrInvalidTarget)
	}
	if _, ok := NormalizeSlackTarget(d.TargetType); !ok {
		return fmt.Errorf("%w: slack delivery requires a supported target type", ErrInvalidTarget)
	}
	return d.Content.Validate()
}

func (d SlackDelivery) dedupKey() string {
	return ""
}

type Content struct {
	Channel string
	Email   *EmailContent
	Slack   *SlackContent
}

func (c Content) Validate() error {
	channel, ok := NormalizeDeliveryChannel(c.Channel)
	if !ok {
		return fmt.Errorf("%w: content channel %q", ErrInvalidContent, c.Channel)
	}

	switch channel {
	case DeliveryChannelEmail:
		if c.Email == nil {
			return fmt.Errorf("%w: missing email content for channel %q", ErrInvalidContent, c.Channel)
		}
		if c.Slack != nil {
			return fmt.Errorf("%w: email content cannot include slack payload", ErrInvalidContent)
		}
		if err := c.Email.Validate(); err != nil {
			return err
		}
	case DeliveryChannelSlack:
		if c.Slack == nil {
			return fmt.Errorf("%w: missing slack content for channel %q", ErrInvalidContent, c.Channel)
		}
		if c.Email != nil {
			return fmt.Errorf("%w: slack content cannot include email payload", ErrInvalidContent)
		}
		if err := c.Slack.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c Content) Clone() Content {
	cloned := Content{Channel: c.Channel}
	if c.Email != nil {
		email := c.Email.Clone()
		cloned.Email = &email
	}
	if c.Slack != nil {
		slack := c.Slack.Clone()
		cloned.Slack = &slack
	}
	return cloned
}

type Delivery struct {
	Channel  string
	Target   Target
	Content  Content
	Metadata TransportMetadata
}

func (d Delivery) Validate() error {
	channel, ok := NormalizeDeliveryChannel(d.Channel)
	if !ok {
		return fmt.Errorf("%w: delivery channel %q", ErrInvalidTarget, d.Channel)
	}
	if err := d.Target.Validate(); err != nil {
		return err
	}
	if d.Target.Channel != channel {
		return fmt.Errorf("%w: target channel %q does not match delivery channel %q", ErrInvalidTarget, d.Target.Channel, d.Channel)
	}
	if err := d.Content.Validate(); err != nil {
		return err
	}
	if d.Content.Channel != channel {
		return fmt.Errorf("%w: content channel %q does not match delivery channel %q", ErrInvalidContent, d.Content.Channel, d.Channel)
	}

	return nil
}

type TransportMetadata struct {
	NotificationKind Kind
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
	Channel    string
	Address    string
	Attributes map[string]string
}

func (d ConfiguredDestination) Validate() error {
	return Target{
		Channel:    d.Channel,
		Address:    d.Address,
		Attributes: d.Attributes,
	}.Validate()
}
