package notification

import "fmt"

type testEmailContent struct {
	From     string
	Subject  string
	HTMLBody string
	TextBody string
}

func (c testEmailContent) Validate() error {
	if c.From == "" {
		return fmt.Errorf("%w: test email content requires from address", ErrInvalidContent)
	}
	if c.Subject == "" {
		return fmt.Errorf("%w: test email content requires subject", ErrInvalidContent)
	}
	if c.HTMLBody == "" && c.TextBody == "" {
		return fmt.Errorf("%w: test email content requires html or text body", ErrInvalidContent)
	}
	return nil
}

func (c testEmailContent) ClonePayload() any {
	return c
}

type testEmailDelivery struct {
	To      string
	Content testEmailContent
}

func (d testEmailDelivery) Validate() error {
	if d.To == "" {
		return fmt.Errorf("%w: test email delivery requires recipient", ErrInvalidTarget)
	}
	return d.Content.Validate()
}
