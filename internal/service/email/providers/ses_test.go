package providers

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/compliance-framework/api/internal/config"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeSESClient struct {
	sendInput  *sesv2.SendEmailInput
	sendOutput *sesv2.SendEmailOutput
	sendErr    error
	accountErr error
}

func (f *fakeSESClient) SendEmail(ctx context.Context, input *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.sendInput = input
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	if f.sendOutput != nil {
		return f.sendOutput, nil
	}
	return &sesv2.SendEmailOutput{
		MessageId: input.FromEmailAddress,
	}, nil
}

func (f *fakeSESClient) GetAccount(ctx context.Context, input *sesv2.GetAccountInput, _ ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	if f.accountErr != nil {
		return nil, f.accountErr
	}
	return &sesv2.GetAccountOutput{}, nil
}

func newSESProviderWithClient(cfg *config.SESConfig, client sesClient) *sesProvider {
	return &sesProvider{
		config: cfg,
		logger: zap.NewNop().Sugar(),
		client: client,
	}
}

func TestSESProviderSend_Success(t *testing.T) {
	cfg := &config.SESConfig{
		Name:    "AWS SES",
		Enabled: true,
		Region:  "us-east-1",
		From:    "noreply@example.com",
	}
	fakeClient := &fakeSESClient{
		sendOutput: &sesv2.SendEmailOutput{
			MessageId: awsString("msg-123"),
		},
	}

	provider := newSESProviderWithClient(cfg, fakeClient)

	msg := &emailtypes.Message{
		To:       []string{"user@example.com"},
		Subject:  "Hello",
		TextBody: "Plain body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.NoError(t, err)
	require.True(t, result.Success)
	require.Equal(t, "msg-123", result.MessageID)
	require.Equal(t, cfg.From, *fakeClient.sendInput.FromEmailAddress)
	require.Equal(t, []string{"user@example.com"}, fakeClient.sendInput.Destination.ToAddresses)
}

func TestSESProviderSend_Error(t *testing.T) {
	cfg := &config.SESConfig{
		From: "noreply@example.com",
	}

	fakeClient := &fakeSESClient{
		sendErr: errTestFailure,
	}
	provider := newSESProviderWithClient(cfg, fakeClient)

	msg := &emailtypes.Message{
		To:       []string{"user@example.com"},
		Subject:  "Hello",
		TextBody: "Plain body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.Error(t, err)
	require.False(t, result.Success)
	require.Equal(t, errTestFailure.Error(), result.Error)
}

func TestSESProviderSend_NoRecipients(t *testing.T) {
	cfg := &config.SESConfig{From: "noreply@example.com"}
	provider := newSESProviderWithClient(cfg, &fakeSESClient{})

	msg := &emailtypes.Message{
		Subject: "Hello",
	}

	result, err := provider.Send(context.Background(), msg)
	require.Error(t, err)
	require.Nil(t, result)
}

func TestSESProviderIsHealthy(t *testing.T) {
	cfg := &config.SESConfig{}
	client := &fakeSESClient{}
	provider := newSESProviderWithClient(cfg, client)

	err := provider.IsHealthy(context.Background())
	require.NoError(t, err)

	client.accountErr = errTestFailure
	err = provider.IsHealthy(context.Background())
	require.Error(t, err)
}

var errTestFailure = errors.New("test failure")

func awsString(v string) *string {
	return &v
}
