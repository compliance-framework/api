package email

import (
	"context"
	"fmt"
	"strings"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
)

type Sender interface {
	IsEnabled() bool
	Send(ctx context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error)
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

type Provider struct {
	senderProvider          SenderProvider
	enqueuerProvider        EnqueuerProvider
	contentRendererProvider ContentRendererProvider
}

func NewProvider(senderProvider SenderProvider, enqueuerProvider EnqueuerProvider) *Provider {
	return &Provider{senderProvider: senderProvider, enqueuerProvider: enqueuerProvider}
}

func NewProviderWithTemplateRenderer(
	senderProvider SenderProvider,
	enqueuerProvider EnqueuerProvider,
	contentRendererProvider ContentRendererProvider,
) *Provider {
	return &Provider{
		senderProvider:          senderProvider,
		enqueuerProvider:        enqueuerProvider,
		contentRendererProvider: contentRendererProvider,
	}
}

func (p *Provider) ID() string { return ChannelID }

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
