package notification

import (
	"context"
	"testing"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubWorkerEnqueuer struct {
	started bool
	emails  []EmailDelivery
}

func (s *stubWorkerEnqueuer) IsStarted() bool {
	return s.started
}

func (s *stubWorkerEnqueuer) EnqueueNotificationEmail(_ context.Context, delivery EmailDelivery) error {
	s.emails = append(s.emails, delivery)
	return nil
}

type stubSlackEnqueuer struct {
	started bool
	slacks  []stubSlackDelivery
}

func (s *stubSlackEnqueuer) IsStarted() bool {
	return s.started
}

func (s *stubSlackEnqueuer) EnqueueNotificationSlack(_ context.Context, delivery stubSlackDelivery) error {
	s.slacks = append(s.slacks, delivery)
	return nil
}

type stubEmailSender struct {
	enabled  bool
	messages []*emailtypes.Message
}

func (s *stubEmailSender) IsEnabled() bool {
	return s.enabled
}

func (s *stubEmailSender) Send(_ context.Context, message *emailtypes.Message) (*emailtypes.SendResult, error) {
	s.messages = append(s.messages, message)
	return &emailtypes.SendResult{Success: true, MessageID: "email-1"}, nil
}

type stubSlackSender struct {
	enabled  bool
	channels []string
	messages []*slacktypes.Message
}

func (s *stubSlackSender) IsEnabled() bool {
	return s.enabled
}

func (s *stubSlackSender) SendMessage(_ context.Context, channel string, message *slacktypes.Message) (*slacktypes.SendResult, error) {
	s.channels = append(s.channels, channel)
	s.messages = append(s.messages, message)
	return &slacktypes.SendResult{Success: true, Channel: channel, DeliveryID: "slack-1"}, nil
}

type stubSlackContent struct {
	Text string
}

type stubSlackDelivery struct {
	Channel string
	Text    string
}

type testSlackProvider struct {
	sender   *stubSlackSender
	enqueuer *stubSlackEnqueuer
}

func (p *testSlackProvider) ID() string { return DeliveryChannelSlack }

func (p *testSlackProvider) ResolveUserTarget(_ User) (Target, bool, error) {
	return Target{}, false, nil
}

func (p *testSlackProvider) ValidateTarget(target Target) error {
	if target.Address["channel"] == "" {
		return ErrInvalidTarget
	}
	return nil
}

func (p *testSlackProvider) Deliver(ctx context.Context, delivery Delivery) error {
	payload, ok := delivery.Content.Payload.(stubSlackContent)
	if !ok {
		return ErrInvalidContent
	}
	channel := delivery.Target.Address["channel"]

	if p.enqueuer != nil && p.enqueuer.started {
		return p.enqueuer.EnqueueNotificationSlack(ctx, stubSlackDelivery{Channel: channel, Text: payload.Text})
	}

	if p.sender == nil || !p.sender.enabled {
		return nil
	}
	_, err := p.sender.SendMessage(ctx, channel, &slacktypes.Message{Text: payload.Text, Blocks: []slack.Block{}})
	return err
}

func TestDeliveryTransportUsesWorkerWhenStarted(t *testing.T) {
	worker := &stubWorkerEnqueuer{started: true}
	slackEnqueuer := &stubSlackEnqueuer{started: true}
	emailSender := &stubEmailSender{enabled: true}
	slackSender := &stubSlackSender{enabled: true}

	transport := NewDeliveryTransport(
		WithWorkerEnqueuerProvider(func() WorkerEnqueuer { return worker }),
		WithEmailSenderProvider(func() EmailSender { return emailSender }),
		WithProvider(&testSlackProvider{sender: slackSender, enqueuer: slackEnqueuer}),
	)

	err := transport.Enqueue(context.Background(), []Delivery{
		{
			Provider: DeliveryChannelEmail,
			Target:   Target{Provider: DeliveryChannelEmail, Address: map[string]string{"email": "alice@example.com"}},
			Content: Content{Provider: DeliveryChannelEmail, Payload: EmailContent{
				From:     "from@example.com",
				Subject:  "Subject",
				TextBody: "body",
			}},
		},
		{
			Provider: DeliveryChannelSlack,
			Target:   Target{Provider: DeliveryChannelSlack, Address: map[string]string{"channel": "UALICE", "target_type": "direct_message"}},
			Content: Content{Provider: DeliveryChannelSlack, Payload: stubSlackContent{
				Text: "body",
			}},
		},
	})
	require.NoError(t, err)

	require.Len(t, worker.emails, 1)
	require.Len(t, slackEnqueuer.slacks, 1)
	assert.Empty(t, emailSender.messages)
	assert.Empty(t, slackSender.messages)
}

func TestDeliveryTransportFallsBackToDirectSend(t *testing.T) {
	emailSender := &stubEmailSender{enabled: true}
	slackSender := &stubSlackSender{enabled: true}

	transport := NewDeliveryTransport(
		WithEmailSenderProvider(func() EmailSender { return emailSender }),
		WithProvider(&testSlackProvider{sender: slackSender}),
	)

	err := transport.Enqueue(context.Background(), []Delivery{
		{
			Provider: DeliveryChannelEmail,
			Target:   Target{Provider: DeliveryChannelEmail, Address: map[string]string{"email": "alice@example.com"}},
			Content: Content{Provider: DeliveryChannelEmail, Payload: EmailContent{
				From:     "from@example.com",
				Subject:  "Subject",
				TextBody: "body",
			}},
		},
		{
			Provider: DeliveryChannelSlack,
			Target:   Target{Provider: DeliveryChannelSlack, Address: map[string]string{"channel": "C-DIGEST", "target_type": "channel"}},
			Content: Content{Provider: DeliveryChannelSlack, Payload: stubSlackContent{
				Text: "body",
			}},
		},
	})
	require.NoError(t, err)

	require.Len(t, emailSender.messages, 1)
	assert.Equal(t, "alice@example.com", emailSender.messages[0].To[0])
	require.Len(t, slackSender.messages, 1)
	assert.Equal(t, "C-DIGEST", slackSender.channels[0])
}
