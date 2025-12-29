package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateService_Use(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	data := TemplateData{
		"FirstName": "John",
		"ResetURL":  "http://localhost:8000/auth/password-reset?token=abc123",
	}

	html, text, err := service.Use("forgot-password", data)
	require.NoError(t, err, "Failed to use template")
	require.NotEmpty(t, html, "HTML content should not be empty")
	require.NotEmpty(t, text, "Text content should not be empty")
	require.Contains(t, html, "Hello John")
	require.Contains(t, text, "Hello John")
	require.Contains(t, html, data["ResetURL"].(string))
	require.Contains(t, text, data["ResetURL"].(string))
}

func TestTemplateService_UseHTMLAndUseText(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	data := TemplateData{
		"FirstName": "Alice",
		"ResetURL":  "http://localhost/reset?token=xyz",
	}

	htmlContent, err := service.UseHTML("forgot-password", data)
	require.NoError(t, err, "UseHTML should render known template")
	require.Contains(t, htmlContent, "Alice")
	require.Contains(t, htmlContent, data["ResetURL"].(string))

	textContent, err := service.UseText("forgot-password", data)
	require.NoError(t, err, "UseText should render known template")
	require.Contains(t, textContent, "Alice")
	require.Contains(t, textContent, data["ResetURL"].(string))
}

func TestTemplateService_MissingTemplates(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	_, err = service.UseHTML("missing-template", TemplateData{})
	require.Error(t, err, "UseHTML should error for missing template")

	_, err = service.UseText("missing-template", TemplateData{})
	require.Error(t, err, "UseText should error for missing template")
}

func TestTemplateService_ListTemplates(t *testing.T) {
	service, err := NewTemplateService()
	require.NoError(t, err, "Failed to create template service")

	templates := service.ListTemplates()
	require.NotEmpty(t, templates, "Should have at least one template")

	found := false
	for _, tmpl := range templates {
		if tmpl == "forgot-password" {
			found = true
			break
		}
	}
	require.True(t, found, "Should contain 'forgot-password' template")
}
