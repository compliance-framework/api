package types

import (
	"context"

	"github.com/compliance-framework/api/internal/config"
)

// Message represents an email message
type Message struct {
	From        string            `json:"from"`
	FromName    string            `json:"from_name"`
	To          []string          `json:"to"`
	Cc          []string          `json:"cc,omitempty"`
	Bcc         []string          `json:"bcc,omitempty"`
	Subject     string            `json:"subject"`
	HTMLBody    string            `json:"html_body,omitempty"`
	TextBody    string            `json:"text_body,omitempty"`
	Attachments []Attachment      `json:"attachments,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
	Inline      bool   `json:"inline,omitempty"`
}

// SendResult represents the result of sending an email
type SendResult struct {
	MessageID string `json:"message_id,omitempty"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// Provider defines the interface that all email providers must implement
type Provider interface {
	// Send sends an email message
	Send(ctx context.Context, message *Message) (*SendResult, error)

	// SendTemplate sends an email using a template (optional implementation)
	SendTemplate(ctx context.Context, template string, data interface{}, message *Message) (*SendResult, error)

	// GetProviderConfig returns the provider configuration
	GetProviderConfig() config.EmailProviderSettings

	// GetName returns the provider name
	GetName() string

	// GetType returns the provider type (smtp, sendgrid, ses, etc)
	GetType() string

	// IsHealthy checks if the provider is healthy/reachable
	IsHealthy(ctx context.Context) error

	// Close closes any resources held by the provider
	Close() error
}
