package worker

import (
	"context"
	"fmt"

	emailprovider "github.com/compliance-framework/api/internal/service/notification/providers/email"
)

func renderPoamOpenDigestEmail(_ context.Context, model any) (emailprovider.TemplateContent, error) {
	digestModel, err := poamOpenDigestNotificationModelFromAny(model)
	if err != nil {
		return emailprovider.TemplateContent{}, err
	}

	return emailprovider.TemplateContent{
		TemplateName: "poam-open-digest",
		TemplateData: digestModel.templateData(),
		Subject:      fmt.Sprintf("Your POAM digest — %s", formatDate(digestModel.GeneratedAt)),
		TextBody:     "Your POAM digest is ready.",
	}, nil
}
