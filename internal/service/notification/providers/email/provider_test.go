package email

import (
	"context"
	"errors"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubSender struct {
	enabled  bool
	messages []*emailtypes.Message
	err      error
	result   *emailtypes.SendResult
}

func (s *stubSender) IsEnabled() bool {
	return s.enabled
}

func (s *stubSender) Send(_ context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error) {
	s.messages = append(s.messages, message)
	if s.result != nil || s.err != nil {
		return s.result, s.err
	}
	return &emailtypes.SendResult{Success: true, MessageID: "email-1"}, nil
}

type stubEnqueuer struct {
	started    bool
	deliveries []Delivery
	err        error
}

func (e *stubEnqueuer) IsStarted() bool {
	return e.started
}

func (e *stubEnqueuer) EnqueueNotificationEmail(_ context.Context, delivery Delivery) ([]int64, error) {
	e.deliveries = append(e.deliveries, delivery)
	return []int64{int64(len(e.deliveries))}, e.err
}

type stubTemplateRenderer struct {
	content Content
	err     error
}

func (r *stubTemplateRenderer) RenderTemplate(_ context.Context, _ TemplateContent) (Content, error) {
	if r.err != nil {
		return Content{}, r.err
	}
	return r.content, nil
}

func TestResolveUserTargetFallsBackToUserEmail(t *testing.T) {
	provider := NewProvider(nil, nil)

	target, ok, err := provider.ResolveUserTarget(notification.User{ID: "u-1", Email: " alice@example.com "})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, ChannelID, target.Provider)
	assert.Equal(t, map[string]string{AddressKeyEmail: "alice@example.com"}, target.Address)
}

func TestBuildTargetNormalizesEmailAddress(t *testing.T) {
	provider := NewProvider(nil, nil)

	target, err := provider.BuildTarget(" Alice <alice@example.com> ")
	require.NoError(t, err)
	assert.Equal(t, ChannelID, target.Provider)
	assert.Equal(t, map[string]string{AddressKeyEmail: "alice@example.com"}, target.Address)
}

func TestProviderMetadataUsesConfiguredEmailProvider(t *testing.T) {
	provider := NewCatalogProvider(&config.Config{
		Email: &config.EmailConfig{
			Enabled:  true,
			Provider: "smtp",
			Providers: &config.SupportedEmailProviders{
				SMTP: &config.SMTPConfig{
					Name:    "smtp-primary",
					Enabled: true,
					Host:    "smtp.example.com",
					Port:    587,
					From:    "alerts@example.com",
				},
			},
		},
	})

	metadata := provider.ProviderMetadata()
	assert.Equal(t, notification.ProviderMetadata{
		ProviderType: ChannelID,
		DisplayName:  "Email",
		Description:  "Configured SMTP provider for email service",
		Enabled:      true,
		Metadata: map[string]string{
			MetadataKeyServiceProviderName: "smtp-primary",
			MetadataKeyServiceProviderType: "smtp",
		},
	}, metadata)
}

func TestDisplayTargetRejectsInvalidEmailAddress(t *testing.T) {
	provider := NewProvider(nil, nil)

	_, err := provider.DisplayTarget(notification.Target{
		Provider: ChannelID,
		Address:  map[string]string{AddressKeyEmail: "not-an-email"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, notification.ErrInvalidTarget)
}

func TestDeliverUsesEnqueuerWhenStarted(t *testing.T) {
	enqueuer := &stubEnqueuer{started: true}
	sender := &stubSender{enabled: true}
	provider := NewProvider(func() Sender { return sender }, func() Enqueuer { return enqueuer })

	err := provider.Deliver(context.Background(), notification.Delivery{
		Provider: ChannelID,
		Target: notification.Target{
			Provider: ChannelID,
			Address:  map[string]string{AddressKeyEmail: "alice@example.com"},
		},
		Content: notification.Content{Provider: ChannelID, Payload: Content{
			From:     "from@example.com",
			Subject:  "Subject",
			TextBody: "Body",
		}},
	})
	require.NoError(t, err)
	require.Len(t, enqueuer.deliveries, 1)
	assert.Empty(t, sender.messages)
	assert.Equal(t, "alice@example.com", enqueuer.deliveries[0].To)
}

func TestDeliverFallsBackToSender(t *testing.T) {
	sender := &stubSender{enabled: true}
	provider := NewProvider(func() Sender { return sender }, nil)

	err := provider.Deliver(context.Background(), notification.Delivery{
		Provider: ChannelID,
		Target: notification.Target{
			Provider: ChannelID,
			Address:  map[string]string{AddressKeyEmail: "alice@example.com"},
		},
		Content: notification.Content{Provider: ChannelID, Payload: Content{
			From:     "from@example.com",
			Subject:  "Subject",
			TextBody: "Body",
			Headers:  map[string]string{"X-Test": "1"},
		}},
	})
	require.NoError(t, err)
	require.Len(t, sender.messages, 1)
	assert.Equal(t, []string{"alice@example.com"}, sender.messages[0].To)
	assert.Equal(t, "1", sender.messages[0].Headers["X-Test"])
}

func TestDeliverSkipsWhenSenderIsDisabled(t *testing.T) {
	sender := &stubSender{enabled: false}
	provider := NewProvider(func() Sender { return sender }, nil)

	err := provider.Deliver(context.Background(), notification.Delivery{
		Provider: ChannelID,
		Target: notification.Target{
			Provider: ChannelID,
			Address:  map[string]string{AddressKeyEmail: "alice@example.com"},
		},
		Content: notification.Content{Provider: ChannelID, Payload: Content{
			From:     "from@example.com",
			Subject:  "Subject",
			TextBody: "Body",
		}},
	})
	require.NoError(t, err)
	assert.Empty(t, sender.messages)
}

func TestDeliverReturnsSendError(t *testing.T) {
	sender := &stubSender{enabled: true, err: errors.New("boom")}
	provider := NewProvider(func() Sender { return sender }, nil)

	err := provider.Deliver(context.Background(), notification.Delivery{
		Provider: ChannelID,
		Target: notification.Target{
			Provider: ChannelID,
			Address:  map[string]string{AddressKeyEmail: "alice@example.com"},
		},
		Content: notification.Content{Provider: ChannelID, Payload: Content{
			From:     "from@example.com",
			Subject:  "Subject",
			TextBody: "Body",
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "send email delivery")
}

func TestDeliverRendersTemplatePayload(t *testing.T) {
	sender := &stubSender{enabled: true}
	renderer := &stubTemplateRenderer{content: Content{
		From:     "from@example.com",
		Subject:  "Rendered subject",
		TextBody: "Rendered body",
	}}
	provider := NewProviderWithTemplateRenderer(
		func() Sender { return sender },
		nil,
		func() ContentRenderer { return renderer },
	)

	err := provider.Deliver(context.Background(), notification.Delivery{
		Provider: ChannelID,
		Target: notification.Target{
			Provider: ChannelID,
			Address:  map[string]string{AddressKeyEmail: "alice@example.com"},
		},
		Content: notification.Content{Provider: ChannelID, Payload: TemplateContent{
			TemplateName: "workflow-task-assigned",
			TemplateData: map[string]any{"UserName": "Alice"},
			Subject:      "Rendered subject",
			TextBody:     "Fallback body",
		}},
	})
	require.NoError(t, err)
	require.Len(t, sender.messages, 1)
	assert.Equal(t, "Rendered subject", sender.messages[0].Subject)
	assert.Equal(t, "Rendered body", sender.messages[0].TextBody)
}

func TestDeliverFallsBackForTemplatePayloadWithoutRenderer(t *testing.T) {
	sender := &stubSender{enabled: true}
	provider := NewProvider(func() Sender { return sender }, nil)

	err := provider.Deliver(context.Background(), notification.Delivery{
		Provider: ChannelID,
		Target: notification.Target{
			Provider: ChannelID,
			Address:  map[string]string{AddressKeyEmail: "alice@example.com"},
		},
		Content: notification.Content{Provider: ChannelID, Payload: TemplateContent{
			TemplateName: "workflow-task-assigned",
			Subject:      "Fallback subject",
			TextBody:     "Fallback body",
		}},
	})
	require.NoError(t, err)
	require.Len(t, sender.messages, 1)
	assert.Equal(t, "noreply@localhost", sender.messages[0].From)
	assert.Equal(t, "Fallback subject", sender.messages[0].Subject)
	assert.Equal(t, "Fallback body", sender.messages[0].TextBody)
}
