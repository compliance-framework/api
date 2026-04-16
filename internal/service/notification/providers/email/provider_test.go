package email

import (
	"context"
	"errors"
	"testing"

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

func (e *stubEnqueuer) EnqueueNotificationEmail(_ context.Context, delivery Delivery) error {
	e.deliveries = append(e.deliveries, delivery)
	return e.err
}

func TestResolveUserTargetFallsBackToUserEmail(t *testing.T) {
	provider := NewProvider(nil, nil)

	target, ok, err := provider.ResolveUserTarget(notification.User{ID: "u-1", Email: " alice@example.com "})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, ChannelID, target.Provider)
	assert.Equal(t, map[string]string{AddressKeyEmail: "alice@example.com"}, target.Address)
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
