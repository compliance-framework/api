package email

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/compliance-framework/api/internal/config"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
)

type Sender interface {
	IsEnabled() bool
	Send(ctx context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error)
}

type ServiceProviderDescriptor struct {
	Name string
	Type string
}

type Enqueuer interface {
	IsStarted() bool
	EnqueueNotificationEmail(ctx context.Context, delivery Delivery) error
}

type ContentRenderer interface {
	RenderTemplate(ctx context.Context, content TemplateContent) (Content, error)
}

type SenderProvider func() Sender

type EnqueuerProvider func() Enqueuer

type ContentRendererProvider func() ContentRenderer

type ServiceProviderResolver func() ServiceProviderDescriptor

type EnabledResolver func() bool

type ProviderOption func(*Provider)

type Provider struct {
	senderProvider          SenderProvider
	enqueuerProvider        EnqueuerProvider
	contentRendererProvider ContentRendererProvider
	serviceProviderResolver ServiceProviderResolver
	enabledResolver         EnabledResolver
}

const (
	MetadataKeyServiceProviderName = "service-provider-name"
	MetadataKeyServiceProviderType = "service-provider-type"
)

func NewCatalogProvider(cfg *config.Config) *Provider {
	var emailConfig *config.EmailConfig
	if cfg != nil {
		emailConfig = cfg.Email
	}

	return NewProvider(
		nil,
		nil,
		WithEnabledResolver(func() bool {
			return emailEnabledFromConfig(emailConfig)
		}),
		WithServiceProviderResolver(func() ServiceProviderDescriptor {
			return serviceProviderDescriptorFromConfig(emailConfig)
		}),
	)
}

func NewProvider(senderProvider SenderProvider, enqueuerProvider EnqueuerProvider, opts ...ProviderOption) *Provider {
	provider := &Provider{senderProvider: senderProvider, enqueuerProvider: enqueuerProvider}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	return provider
}

func NewProviderWithTemplateRenderer(
	senderProvider SenderProvider,
	enqueuerProvider EnqueuerProvider,
	contentRendererProvider ContentRendererProvider,
) *Provider {
	return NewProviderWithTemplateRendererOptions(senderProvider, enqueuerProvider, contentRendererProvider)
}

func NewProviderWithTemplateRendererOptions(
	senderProvider SenderProvider,
	enqueuerProvider EnqueuerProvider,
	contentRendererProvider ContentRendererProvider,
	opts ...ProviderOption,
) *Provider {
	provider := &Provider{
		senderProvider:          senderProvider,
		enqueuerProvider:        enqueuerProvider,
		contentRendererProvider: contentRendererProvider,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(provider)
		}
	}
	return provider
}

func WithServiceProviderResolver(resolver ServiceProviderResolver) ProviderOption {
	return func(provider *Provider) {
		if provider == nil {
			return
		}
		provider.serviceProviderResolver = resolver
	}
}

func WithEnabledResolver(resolver EnabledResolver) ProviderOption {
	return func(provider *Provider) {
		if provider == nil {
			return
		}
		provider.enabledResolver = resolver
	}
}

func (p *Provider) ID() string { return ChannelID }

func (p *Provider) ProviderMetadata() notification.ProviderMetadata {
	metadata := notification.ProviderMetadata{
		ProviderType: ChannelID,
		DisplayName:  "Email",
		Description:  "Configured provider for email service",
		Enabled:      p.enabled(),
	}

	serviceProvider := p.serviceProvider()
	if serviceProvider.Type != "" {
		metadata.Description = fmt.Sprintf("Configured %s provider for email service", strings.ToUpper(serviceProvider.Type))
	}
	if serviceProvider.Name != "" || serviceProvider.Type != "" {
		metadata.Metadata = map[string]string{}
		if serviceProvider.Name != "" {
			metadata.Metadata[MetadataKeyServiceProviderName] = serviceProvider.Name
		}
		if serviceProvider.Type != "" {
			metadata.Metadata[MetadataKeyServiceProviderType] = serviceProvider.Type
		}
	}

	return metadata
}

type senderServiceProviderDescriptor interface {
	GetDefaultProviderName() string
	GetDefaultProviderType() string
}

func serviceProviderDescriptorFromConfig(cfg *config.EmailConfig) ServiceProviderDescriptor {
	if cfg == nil {
		return ServiceProviderDescriptor{}
	}

	provider := cfg.GetDefaultProvider()
	if provider == nil {
		return ServiceProviderDescriptor{}
	}

	return ServiceProviderDescriptor{
		Name: strings.TrimSpace(provider.GetName()),
		Type: strings.TrimSpace(provider.GetType()),
	}
}

func emailEnabledFromConfig(cfg *config.EmailConfig) bool {
	if cfg == nil || !cfg.Enabled {
		return false
	}

	provider := cfg.GetDefaultProvider()
	return provider != nil && provider.IsEnabled()
}

func (p *Provider) serviceProvider() ServiceProviderDescriptor {
	if p != nil && p.serviceProviderResolver != nil {
		descriptor := p.serviceProviderResolver()
		descriptor.Name = strings.TrimSpace(descriptor.Name)
		descriptor.Type = strings.TrimSpace(descriptor.Type)
		if descriptor.Name != "" || descriptor.Type != "" {
			return descriptor
		}
	}

	sender := p.sender()
	if sender == nil {
		return ServiceProviderDescriptor{}
	}

	descriptorProvider, ok := sender.(senderServiceProviderDescriptor)
	if !ok {
		return ServiceProviderDescriptor{}
	}

	return ServiceProviderDescriptor{
		Name: strings.TrimSpace(descriptorProvider.GetDefaultProviderName()),
		Type: strings.TrimSpace(descriptorProvider.GetDefaultProviderType()),
	}
}

func (p *Provider) enabled() bool {
	if p != nil && p.enabledResolver != nil {
		return p.enabledResolver()
	}

	sender := p.sender()
	return sender != nil && sender.IsEnabled()
}

func (p *Provider) ResolveUserTarget(user notification.User) (notification.Target, bool, error) {
	if len(user.Identities) > 0 {
		identity, ok := user.Identities[ChannelID]
		if ok && len(identity) > 0 {
			address := make(map[string]string, len(identity))
			for key, value := range identity {
				address[key] = strings.TrimSpace(value)
			}
			if strings.TrimSpace(address[AddressKeyEmail]) != "" {
				return notification.Target{
					Provider: ChannelID,
					UserID:   user.ID,
					Address:  address,
				}, true, nil
			}
		}
	}

	address := Identity(user.Email)
	if address == nil {
		return notification.Target{}, false, nil
	}

	return notification.Target{
		Provider: ChannelID,
		UserID:   user.ID,
		Address:  address,
	}, true, nil
}

func (p *Provider) BuildTarget(rawTarget string) (notification.Target, error) {
	return p.NormalizeTarget(notification.Target{
		Provider: ChannelID,
		Address: map[string]string{
			AddressKeyEmail: rawTarget,
		},
	})
}

func (p *Provider) NormalizeTarget(target notification.Target) (notification.Target, error) {
	address := strings.TrimSpace(target.Address[AddressKeyEmail])
	if address == "" {
		return notification.Target{}, fmt.Errorf("%w: email provider requires email address", notification.ErrInvalidTarget)
	}

	parsedAddress, err := mail.ParseAddress(address)
	if err != nil || strings.TrimSpace(parsedAddress.Address) == "" {
		return notification.Target{}, fmt.Errorf("%w: email provider requires email address", notification.ErrInvalidTarget)
	}

	normalized := notification.Target{
		Provider: ChannelID,
		UserID:   strings.TrimSpace(target.UserID),
		Address:  Identity(parsedAddress.Address),
	}
	if err := p.ValidateTarget(normalized); err != nil {
		return notification.Target{}, err
	}

	return normalized, nil
}

func (p *Provider) DisplayTarget(target notification.Target) (string, error) {
	normalized, err := p.NormalizeTarget(target)
	if err != nil {
		return "", err
	}

	return normalized.Address[AddressKeyEmail], nil
}

func (p *Provider) ValidateTarget(target notification.Target) error {
	address := strings.TrimSpace(target.Address[AddressKeyEmail])
	if address == "" {
		return fmt.Errorf("%w: email provider requires email address", notification.ErrInvalidTarget)
	}

	return nil
}

// Deliver prefers enqueuing when a started enqueuer is available. If direct
// sending is the only option and no sender is configured or enabled, delivery
// is treated as a no-op so notifications can be optional in some environments.
func (p *Provider) Deliver(ctx context.Context, delivery notification.Delivery) error {
	emailContent, err := p.extractContent(ctx, delivery.Content.Payload)
	if err != nil {
		return err
	}

	providerDelivery := Delivery{
		To:       strings.TrimSpace(delivery.Target.Address[AddressKeyEmail]),
		Content:  emailContent,
		Metadata: delivery.Metadata,
	}
	if err := providerDelivery.Validate(); err != nil {
		return err
	}

	if enqueuer := p.enqueuer(); enqueuer != nil && enqueuer.IsStarted() {
		if err := enqueuer.EnqueueNotificationEmail(ctx, providerDelivery); err != nil {
			return fmt.Errorf("enqueue email delivery: %w", err)
		}
		return nil
	}

	sender := p.sender()
	if sender == nil || !sender.IsEnabled() {
		return nil
	}

	message := &emailtypes.Message{
		From:        providerDelivery.Content.From,
		To:          []string{providerDelivery.To},
		Subject:     providerDelivery.Content.Subject,
		HTMLBody:    providerDelivery.Content.HTMLBody,
		TextBody:    providerDelivery.Content.TextBody,
		Attachments: append([]emailtypes.Attachment(nil), providerDelivery.Content.Attachments...),
		Headers:     cloneHeaders(providerDelivery.Content.Headers),
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

func (p *Provider) sender() Sender {
	if p == nil || p.senderProvider == nil {
		return nil
	}
	return p.senderProvider()
}

func (p *Provider) enqueuer() Enqueuer {
	if p == nil || p.enqueuerProvider == nil {
		return nil
	}
	return p.enqueuerProvider()
}

func (p *Provider) contentRenderer() ContentRenderer {
	if p == nil || p.contentRendererProvider == nil {
		return nil
	}
	return p.contentRendererProvider()
}

func (p *Provider) extractContent(ctx context.Context, payload any) (Content, error) {
	switch typed := payload.(type) {
	case Content:
		return typed.Clone(), nil
	case *Content:
		if typed == nil {
			return Content{}, fmt.Errorf("missing email content")
		}
		return typed.Clone(), nil
	case TemplateContent:
		return p.renderTemplateContent(ctx, typed.Clone())
	case *TemplateContent:
		if typed == nil {
			return Content{}, fmt.Errorf("missing email template content")
		}
		return p.renderTemplateContent(ctx, typed.Clone())
	default:
		return Content{}, fmt.Errorf("email provider expects email.Content or email.TemplateContent payload, got %T", payload)
	}
}

func (p *Provider) renderTemplateContent(ctx context.Context, content TemplateContent) (Content, error) {
	if renderer := p.contentRenderer(); renderer != nil {
		rendered, err := renderer.RenderTemplate(ctx, content)
		if err != nil {
			return Content{}, err
		}
		return rendered, nil
	}

	return content.FallbackContent()
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}

	return cloned
}
