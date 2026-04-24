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

type TemplateContent struct {
	TemplateName string
	TemplateData map[string]any
	From         string
	Subject      string
	HTMLBody     string
	TextBody     string
	Attachments  []emailtypes.Attachment
	Headers      map[string]string
}

func (c TemplateContent) Validate() error {
	if strings.TrimSpace(c.Subject) == "" {
		return fmt.Errorf("%w: email template content requires subject", notification.ErrInvalidContent)
	}
	if strings.TrimSpace(c.TemplateName) == "" && strings.TrimSpace(c.HTMLBody) == "" && strings.TrimSpace(c.TextBody) == "" {
		return fmt.Errorf("%w: email template content requires template name or fallback body", notification.ErrInvalidContent)
	}
	return nil
}

func (c TemplateContent) Clone() TemplateContent {
	cloned := c
	if len(c.TemplateData) > 0 {
		cloned.TemplateData = make(map[string]any, len(c.TemplateData))
		for key, value := range c.TemplateData {
			cloned.TemplateData[key] = value
		}
	}
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

func (c TemplateContent) ClonePayload() any {
	return c.Clone()
}

func (c TemplateContent) FallbackContent() (Content, error) {
	if err := c.Validate(); err != nil {
		return Content{}, err
	}

	from := strings.TrimSpace(c.From)
	if from == "" {
		from = "noreply@localhost"
	}

	return Content{
		From:        from,
		Subject:     strings.TrimSpace(c.Subject),
		HTMLBody:    c.HTMLBody,
		TextBody:    c.TextBody,
		Attachments: append([]emailtypes.Attachment(nil), c.Attachments...),
		Headers:     cloneHeaders(c.Headers),
	}, nil
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
