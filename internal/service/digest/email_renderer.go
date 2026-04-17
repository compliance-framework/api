package digest

import (
	"context"
	"fmt"
	"strings"

	"github.com/compliance-framework/api/internal/service/email"
	emailtypes "github.com/compliance-framework/api/internal/service/email/types"
	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
)

type digestNotificationEmailTemplateRenderer struct {
	emailService *email.Service
}

func newDigestNotificationEmailTemplateRenderer(emailService *email.Service) emailprovider.ContentRenderer {
	if emailService == nil {
		return nil
	}
	return &digestNotificationEmailTemplateRenderer{emailService: emailService}
}

func renderEvidenceDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := evidenceDigestModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "evidence-digest",
		TemplateData: digestModel.templateData(),
		Subject:      "Evidence Compliance Digest",
		TextBody:     "Evidence compliance digest is ready.",
	}, nil
}

func (r *digestNotificationEmailTemplateRenderer) RenderTemplate(_ context.Context, content emailprovider.TemplateContent) (emailprovider.Content, error) {
	if r == nil || r.emailService == nil {
		return content.FallbackContent()
	}

	htmlContent, textContent, err := r.emailService.UseTemplate(content.TemplateName, content.TemplateData)
	if err != nil {
		return emailprovider.Content{}, fmt.Errorf("failed to render %s template: %w", content.TemplateName, err)
	}

	from := strings.TrimSpace(content.From)
	if from == "" {
		from = strings.TrimSpace(r.emailService.GetDefaultFromAddress())
	}

	return emailprovider.Content{
		From:        from,
		Subject:     strings.TrimSpace(content.Subject),
		HTMLBody:    htmlContent,
		TextBody:    textContent,
		Attachments: append([]emailtypes.Attachment(nil), content.Attachments...),
		Headers:     cloneDigestNotificationEmailHeaders(content.Headers),
	}, nil
}

func cloneDigestNotificationEmailHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}

	return cloned
}
