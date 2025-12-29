package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/smtp"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type fakeSMTPClient struct {
	startTLSCalled bool
	authCalled     bool
	mailArg        string
	rcptArgs       []string
	dataBuffer     *bytes.Buffer
	quitCalled     bool

	startTLSError error
	authError     error
	mailError     error
	rcptError     error
	dataError     error
	writeError    error
}

func (f *fakeSMTPClient) StartTLS(_ *tls.Config) error {
	f.startTLSCalled = true
	return f.startTLSError
}

func (f *fakeSMTPClient) Auth(_ smtp.Auth) error {
	f.authCalled = true
	return f.authError
}

func (f *fakeSMTPClient) Mail(addr string) error {
	f.mailArg = addr
	return f.mailError
}

func (f *fakeSMTPClient) Rcpt(addr string) error {
	f.rcptArgs = append(f.rcptArgs, addr)
	return f.rcptError
}

func (f *fakeSMTPClient) Data() (smtpDataCloser, error) {
	if f.dataError != nil {
		return nil, f.dataError
	}
	if f.dataBuffer == nil {
		f.dataBuffer = &bytes.Buffer{}
	}
	return &fakeSMTPDataCloser{
		buffer:    f.dataBuffer,
		writeErr:  f.writeError,
		closeChan: make(chan struct{}, 1),
	}, nil
}

func (f *fakeSMTPClient) Quit() error {
	f.quitCalled = true
	return nil
}

type fakeSMTPDataCloser struct {
	buffer    *bytes.Buffer
	writeErr  error
	closeChan chan struct{}
}

func (f *fakeSMTPDataCloser) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.buffer.Write(p)
}

func (f *fakeSMTPDataCloser) Close() error {
	f.closeChan <- struct{}{}
	return nil
}

func newTestSMTPProvider(cfg *config.SMTPConfig, dialer smtpClientDialer) *smtpProvider {
	return &smtpProvider{
		config: cfg,
		logger: zap.NewNop().Sugar(),
		dialer: dialer,
	}
}

func TestSMTPProviderSend_Success(t *testing.T) {
	cfg := &config.SMTPConfig{
		Name:    "SMTP",
		Enabled: true,
		Host:    "smtp.example.com",
		Port:    587,
		From:    "noreply@example.com",
	}

	fakeClient := &fakeSMTPClient{dataBuffer: &bytes.Buffer{}}
	dialer := func(ctx context.Context, cfg *config.SMTPConfig) (smtpClient, error) {
		return fakeClient, nil
	}
	provider := newTestSMTPProvider(cfg, dialer)

	msg := &emailtypes.Message{
		To:       []string{"user@example.com"},
		Subject:  "Test Subject",
		TextBody: "Plain text body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.NoError(t, err)
	require.True(t, result.Success)
	require.Equal(t, cfg.From, fakeClient.mailArg)
	require.Equal(t, []string{"user@example.com"}, fakeClient.rcptArgs)
	require.Contains(t, fakeClient.dataBuffer.String(), "Test Subject")
	require.True(t, fakeClient.quitCalled)
}

func TestSMTPProviderSend_StartTLSError(t *testing.T) {
	cfg := &config.SMTPConfig{
		Name:    "SMTP",
		Enabled: true,
		Host:    "smtp.example.com",
		Port:    587,
		From:    "noreply@example.com",
		UseTLS:  true,
	}

	fakeClient := &fakeSMTPClient{
		startTLSError: errors.New("start tls failure"),
		dataBuffer:    &bytes.Buffer{},
	}
	dialer := func(ctx context.Context, cfg *config.SMTPConfig) (smtpClient, error) {
		return fakeClient, nil
	}

	provider := newTestSMTPProvider(cfg, dialer)

	msg := &emailtypes.Message{
		To:       []string{"user@example.com"},
		Subject:  "Test Subject",
		TextBody: "Plain text body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.Error(t, err)
	require.False(t, result.Success)
	require.True(t, fakeClient.startTLSCalled)
}

func TestSMTPProviderSend_AuthError(t *testing.T) {
	cfg := &config.SMTPConfig{
		Name:     "SMTP",
		Enabled:  true,
		Host:     "smtp.example.com",
		Port:     587,
		From:     "noreply@example.com",
		Username: "user",
		Password: "pass",
	}

	fakeClient := &fakeSMTPClient{
		authError:  errors.New("auth failed"),
		dataBuffer: &bytes.Buffer{},
	}
	dialer := func(ctx context.Context, cfg *config.SMTPConfig) (smtpClient, error) {
		return fakeClient, nil
	}

	provider := newTestSMTPProvider(cfg, dialer)

	msg := &emailtypes.Message{
		To:       []string{"user@example.com"},
		Subject:  "Test Subject",
		TextBody: "Plain text body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.Error(t, err)
	require.False(t, result.Success)
	require.True(t, fakeClient.authCalled)
}

func TestSMTPProviderSend_DialerError(t *testing.T) {
	cfg := &config.SMTPConfig{
		Name:    "SMTP",
		Enabled: true,
		Host:    "smtp.example.com",
		Port:    587,
		From:    "noreply@example.com",
	}

	provider := newTestSMTPProvider(cfg, func(ctx context.Context, cfg *config.SMTPConfig) (smtpClient, error) {
		return nil, errors.New("dial failed")
	})

	msg := &emailtypes.Message{
		To:       []string{"user@example.com"},
		Subject:  "Test Subject",
		TextBody: "Plain text body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.Error(t, err)
	require.False(t, result.Success)
}

func TestSMTPProviderSend_NoRecipients(t *testing.T) {
	cfg := &config.SMTPConfig{
		Name:    "SMTP",
		Enabled: true,
		Host:    "smtp.example.com",
		Port:    587,
		From:    "noreply@example.com",
	}

	provider := newTestSMTPProvider(cfg, func(ctx context.Context, cfg *config.SMTPConfig) (smtpClient, error) {
		return &fakeSMTPClient{dataBuffer: &bytes.Buffer{}}, nil
	})

	msg := &emailtypes.Message{
		Subject:  "Test Subject",
		TextBody: "Plain text body",
	}

	result, err := provider.Send(context.Background(), msg)
	require.Error(t, err)
	require.Nil(t, result)
}
