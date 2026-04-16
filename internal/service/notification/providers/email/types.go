package email

import (
	"fmt"
	"strings"

	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	"github.com/compliance-framework/api/internal/service/notification"
)

type Content struct {
	From        string
	Subject     string
	HTMLBody    string
	TextBody    string
	Attachments []emailtypes.Attachment
	Headers     map[string]string
}

func (c Content) Validate() error {
	if strings.TrimSpace(c.From) == "" {
		return fmt.Errorf("%w: email content requires from address", notification.ErrInvalidContent)
	}
	if strings.TrimSpace(c.Subject) == "" {
		return fmt.Errorf("%w: email content requires subject", notification.ErrInvalidContent)
	}
	if strings.TrimSpace(c.HTMLBody) == "" && strings.TrimSpace(c.TextBody) == "" {
		return fmt.Errorf("%w: email content requires html or text body", notification.ErrInvalidContent)
	}
	return nil
}

func (c Content) Clone() Content {
	cloned := c
	if len(c.Attachments) > 0 {
		cloned.Attachments = append([]emailtypes.Attachment(nil), c.Attachments...)
	}
	if len(c.Headers) > 0 {
		cloned.Headers = make(map[string]string, len(c.Headers))
		for key, value := range c.Headers {
			cloned.Headers[key] = value
		}
	}
	return cloned
}

func (c Content) ClonePayload() any {
	return c.Clone()
}

type Delivery struct {
	To       string
	Content  Content
	Metadata notification.TransportMetadata
}

func (d Delivery) Validate() error {
	if strings.TrimSpace(d.To) == "" {
		return fmt.Errorf("%w: email delivery requires recipient", notification.ErrInvalidTarget)
	}
	return d.Content.Validate()
}
