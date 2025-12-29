package templates

import (
	"strings"
	"testing"
)

func TestTemplateService_Use(t *testing.T) {
	service, err := NewTemplateService()
	if err != nil {
		t.Fatalf("Failed to create template service: %v", err)
	}

	data := TemplateData{
		"FirstName": "John",
		"ResetURL":  "http://localhost:8000/auth/password-reset?token=abc123",
	}

	html, text, err := service.Use("forgot-password", data)
	if err != nil {
		t.Fatalf("Failed to use template: %v", err)
	}

	// Check HTML content
	if html == "" {
		t.Error("HTML content should not be empty")
	}
	if !strings.Contains(html, "Hello John") {
		t.Error("HTML should contain 'Hello John'")
	}
	if !strings.Contains(html, "http://localhost:8000/auth/password-reset?token=abc123") {
		t.Error("HTML should contain the reset URL")
	}

	// Check text content
	if text == "" {
		t.Error("Text content should not be empty")
	}
	if !strings.Contains(text, "Hello John") {
		t.Error("Text should contain 'Hello John'")
	}
	if !strings.Contains(text, "http://localhost:8000/auth/password-reset?token=abc123") {
		t.Error("Text should contain the reset URL")
	}
}

func TestTemplateService_ListTemplates(t *testing.T) {
	service, err := NewTemplateService()
	if err != nil {
		t.Fatalf("Failed to create template service: %v", err)
	}

	templates := service.ListTemplates()
	if len(templates) == 0 {
		t.Error("Should have at least one template")
	}

	found := false
	for _, tmpl := range templates {
		if tmpl == "forgot-password" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should contain 'forgot-password' template")
	}
}
