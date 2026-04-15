package notification

import (
	"context"
	"testing"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	slacktypes "github.com/compliance-framework/api/internal/service/slack/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubWorkerEnqueuer struct {
	started bool
	emails  []EmailDelivery
	slacks  []SlackDelivery
}

func (s *stubWorkerEnqueuer) IsStarted() bool {
	return s.started
}

func (s *stubWorkerEnqueuer) EnqueueNotificationEmail(_ context.Context, delivery EmailDelivery) error {
	s.emails = append(s.emails, delivery)
	return nil
}

func (s *stubWorkerEnqueuer) EnqueueNotificationSlack(_ context.Context, delivery SlackDelivery) error {
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

func TestDeliveryTransportUsesWorkerWhenStarted(t *testing.T) {
	worker := &stubWorkerEnqueuer{started: true}
	emailSender := &stubEmailSender{enabled: true}
	slackSender := &stubSlackSender{enabled: true}

	transport := NewDeliveryTransport(
		WithWorkerEnqueuerProvider(func() WorkerEnqueuer { return worker }),
		WithEmailSenderProvider(func() EmailSender { return emailSender }),
		WithSlackSenderProvider(func() SlackSender { return slackSender }),
	)

	err := transport.Enqueue(context.Background(), []Delivery{
		{
			Channel: DeliveryChannelEmail,
			Target:  Target{Channel: DeliveryChannelEmail, Address: "alice@example.com"},
			Content: Content{Channel: DeliveryChannelEmail, Email: &EmailContent{
				From:     "from@example.com",
				Subject:  "Subject",
				TextBody: "body",
			}},
		},
		{
			Channel: DeliveryChannelSlack,
			Target:  Target{Channel: DeliveryChannelSlack, Address: "UALICE", Attributes: map[string]string{"target_type": SlackTargetDirectMessage}},
			Content: Content{Channel: DeliveryChannelSlack, Slack: &SlackContent{
				Text: "body",
			}},
		},
	})
	require.NoError(t, err)

	require.Len(t, worker.emails, 1)
	require.Len(t, worker.slacks, 1)
	assert.Empty(t, emailSender.messages)
	assert.Empty(t, slackSender.messages)
}

func TestDeliveryTransportFallsBackToDirectSend(t *testing.T) {
	emailSender := &stubEmailSender{enabled: true}
	slackSender := &stubSlackSender{enabled: true}

	transport := NewDeliveryTransport(
		WithEmailSenderProvider(func() EmailSender { return emailSender }),
		WithSlackSenderProvider(func() SlackSender { return slackSender }),
	)

	err := transport.Enqueue(context.Background(), []Delivery{
		{
			Channel: DeliveryChannelEmail,
			Target:  Target{Channel: DeliveryChannelEmail, Address: "alice@example.com"},
			Content: Content{Channel: DeliveryChannelEmail, Email: &EmailContent{
				From:     "from@example.com",
				Subject:  "Subject",
				TextBody: "body",
			}},
		},
		{
			Channel: DeliveryChannelSlack,
			Target:  Target{Channel: DeliveryChannelSlack, Address: "C-DIGEST", Attributes: map[string]string{"target_type": SlackTargetChannel}},
			Content: Content{Channel: DeliveryChannelSlack, Slack: &SlackContent{
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
