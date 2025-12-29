package providers

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/smtp"
	"strings"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/email/types"
	"go.uber.org/zap"
)

type smtpClient interface {
	StartTLS(*tls.Config) error
	Auth(smtp.Auth) error
	Mail(string) error
	Rcpt(string) error
	Data() (smtpDataCloser, error)
	Quit() error
}

type smtpDataCloser interface {
	Write([]byte) (int, error)
	Close() error
}

type smtpClientDialer func(ctx context.Context, cfg *config.EmailProviderConfig) (smtpClient, error)

type smtpProvider struct {
	config *config.EmailProviderConfig
	logger *zap.SugaredLogger
	dialer smtpClientDialer
}

// NewSMTPProvider creates a new SMTP email provider
func NewSMTPProvider(ctx context.Context, cfg *config.EmailProviderConfig, logger *zap.SugaredLogger) (types.Provider, error) {
	if strings.ToLower(cfg.Provider) != "smtp" {
		return nil, fmt.Errorf("invalid provider type for SMTP: %s", cfg.Provider)
	}

	provider := &smtpProvider{
		config: cfg,
		logger: logger,
		dialer: defaultSMTPDialer,
	}

	// Test connection during initialization
	if err := provider.IsHealthy(ctx); err != nil {
		return nil, fmt.Errorf("SMTP connection test failed: %w", err)
	}

	logger.Infow("SMTP provider initialized", "host", cfg.Host, "port", cfg.Port, "from", cfg.From)
	return provider, nil
}

func (p *smtpProvider) Send(ctx context.Context, message *types.Message) (*types.SendResult, error) {
	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	// Set default from address if not provided in message
	from := message.From
	if from == "" {
		from = p.config.From
	}
	if from == "" {
		return nil, fmt.Errorf("no from address specified")
	}

	// Set default from name if not provided
	fromName := message.FromName
	if fromName == "" {
		fromName = p.config.FromName
	}

	// Validate recipients
	if len(message.To) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}

	// Build email content
	msg := p.buildEmailMessage(from, fromName, message)

	// Send email
	err := p.sendEmail(ctx, from, message.To, msg)
	if err != nil {
		p.logger.Errorw("Failed to send email", "error", err, "to", message.To)
		return &types.SendResult{
			Success: false,
			Error:   err.Error(),
		}, err
	}

	p.logger.Infow("Email sent successfully", "to", message.To, "subject", message.Subject)
	return &types.SendResult{
		Success: true,
	}, nil
}

func (p *smtpProvider) SendTemplate(ctx context.Context, template string, data interface{}, message *types.Message) (*types.SendResult, error) {
	// SMTP provider doesn't have built-in template support
	// This would need to be implemented at a higher level
	return p.Send(ctx, message)
}

func (p *smtpProvider) GetProviderConfig() *config.EmailProviderConfig {
	return p.config
}

func (p *smtpProvider) GetName() string {
	return p.config.Name
}

func (p *smtpProvider) GetType() string {
	return "smtp"
}

func (p *smtpProvider) IsHealthy(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	// Create a test connection
	var auth smtp.Auth
	if p.config.Username != "" && p.config.Password != "" {
		auth = smtp.PlainAuth("", p.config.Username, p.config.Password, p.config.Host)
	}

	var client *smtp.Client
	var err error

	if p.config.UseSSL {
		// Direct SSL connection
		tlsConfig := &tls.Config{
			ServerName:         p.config.Host,
			InsecureSkipVerify: false,
		}
		conn, err := tls.Dial("tcp", address, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to create SSL connection: %w", err)
		}
		client, err = smtp.NewClient(conn, p.config.Host)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
	} else {
		// Regular connection, upgrade to TLS if requested
		client, err = smtp.Dial(address)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}

		if p.config.UseTLS {
			tlsConfig := &tls.Config{
				ServerName:         p.config.Host,
				InsecureSkipVerify: false,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	defer func() {
		if err := client.Close(); err != nil {
			p.logger.Errorw("Failed to close SMTP client", "error", err)
		}
	}()

	// Test authentication if credentials are provided
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	return nil
}

func (p *smtpProvider) Close() error {
	// SMTP provider doesn't maintain persistent connections
	return nil
}

func (p *smtpProvider) buildEmailMessage(from, fromName string, message *types.Message) string {
	var msg strings.Builder

	// Headers
	if fromName != "" {
		msg.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromName, from))
	} else {
		msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	}

	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(message.To, ", ")))

	if len(message.Cc) > 0 {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(message.Cc, ", ")))
	}

	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", message.Subject))
	msg.WriteString("MIME-Version: 1.0\r\n")

	// Add custom headers
	for key, value := range message.Headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Build body
	if message.HTMLBody != "" && message.TextBody != "" {
		// Multipart message
		boundary := fmt.Sprintf("boundary_%d", time.Now().UnixNano())
		msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		msg.WriteString("\r\n")

		// Text part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(message.TextBody)
		msg.WriteString("\r\n")

		// HTML part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(message.HTMLBody)
		msg.WriteString("\r\n")

		msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else if message.HTMLBody != "" {
		// HTML only
		msg.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(message.HTMLBody)
		msg.WriteString("\r\n")
	} else {
		// Text only
		msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(message.TextBody)
		msg.WriteString("\r\n")
	}

	return msg.String()
}

func (p *smtpProvider) sendEmail(ctx context.Context, from string, to []string, msg string) error {
	var auth smtp.Auth
	if p.config.Username != "" && p.config.Password != "" {
		auth = smtp.PlainAuth("", p.config.Username, p.config.Password, p.config.Host)
	}

	client, err := p.dialer(ctx, p.config)
	if err != nil {
		return err
	}

	defer func() {
		if err := client.Quit(); err != nil {
			p.logger.Errorw("Failed to quit SMTP client", "error", err)
		}
	}()

	if !p.config.UseSSL && p.config.UseTLS {
		tlsConfig := &tls.Config{
			ServerName:         p.config.Host,
			InsecureSkipVerify: false,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	return p.writeMessage(client, from, to, msg)
}

func (p *smtpProvider) writeMessage(client smtpClient, from string, to []string, msg string) error {
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", recipient, err)
		}
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}
	defer func() {
		if err := wc.Close(); err != nil {
			p.logger.Errorw("Failed to close write closer", "error", err)
		}
	}()

	_, err = wc.Write([]byte(msg))
	return err
}

func defaultSMTPDialer(ctx context.Context, cfg *config.EmailProviderConfig) (smtpClient, error) {
	address := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	if cfg.UseSSL {
		tlsConfig := &tls.Config{
			ServerName:         cfg.Host,
			InsecureSkipVerify: false,
		}
		conn, err := tls.Dial("tcp", address, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSL connection: %w", err)
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return nil, fmt.Errorf("failed to create SMTP client: %w", err)
		}
		return &realSMTPClient{client: client}, nil
	}

	client, err := smtp.Dial(address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMTP server: %w", err)
	}

	return &realSMTPClient{client: client}, nil
}

type realSMTPClient struct {
	client *smtp.Client
}

func (c *realSMTPClient) StartTLS(cfg *tls.Config) error {
	return c.client.StartTLS(cfg)
}

func (c *realSMTPClient) Auth(auth smtp.Auth) error {
	if auth == nil {
		return nil
	}
	return c.client.Auth(auth)
}

func (c *realSMTPClient) Mail(from string) error {
	return c.client.Mail(from)
}

func (c *realSMTPClient) Rcpt(to string) error {
	return c.client.Rcpt(to)
}

func (c *realSMTPClient) Data() (smtpDataCloser, error) {
	wc, err := c.client.Data()
	if err != nil {
		return nil, err
	}
	return &realSMTPDataCloser{WriteCloser: wc}, nil
}

func (c *realSMTPClient) Quit() error {
	return c.client.Quit()
}

type realSMTPDataCloser struct {
	io.WriteCloser
}

func (d *realSMTPDataCloser) Write(p []byte) (int, error) {
	return d.WriteCloser.Write(p)
}
