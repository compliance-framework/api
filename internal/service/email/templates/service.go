package templates

import (
	"bytes"
	"embed"
	"fmt"
	htmltpl "html/template"
	"path/filepath"
	"strings"
	texttpl "text/template"
)

//go:embed templates/*
var templateFS embed.FS

// TemplateData represents the data structure for email templates
type TemplateData map[string]interface{}

// TemplateService handles email template rendering
type TemplateService struct {
	htmlTemplates *htmltpl.Template
	textTemplates *texttpl.Template
}

// NewTemplateService creates a new template service
func NewTemplateService() (*TemplateService, error) {
	htmlTemplates, err := loadHTMLTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load HTML templates: %w", err)
	}

	textTemplates, err := loadTextTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to load text templates: %w", err)
	}

	return &TemplateService{
		htmlTemplates: htmlTemplates,
		textTemplates: textTemplates,
	}, nil
}

// Use renders a template with the given data and returns both HTML and text versions
func (ts *TemplateService) Use(templateName string, data TemplateData) (htmlContent, textContent string, err error) {
	// Render HTML version
	htmlContent, err = ts.renderHTML(templateName, data)
	if err != nil {
		return "", "", fmt.Errorf("failed to render HTML template: %w", err)
	}

	// Render text version
	textContent, err = ts.renderText(templateName, data)
	if err != nil {
		return "", "", fmt.Errorf("failed to render text template: %w", err)
	}

	return htmlContent, textContent, nil
}

// UseHTML renders only the HTML version of a template
func (ts *TemplateService) UseHTML(templateName string, data TemplateData) (string, error) {
	return ts.renderHTML(templateName, data)
}

// UseText renders only the text version of a template
func (ts *TemplateService) UseText(templateName string, data TemplateData) (string, error) {
	return ts.renderText(templateName, data)
}

// renderHTML renders an HTML template
func (ts *TemplateService) renderHTML(templateName string, data TemplateData) (string, error) {
	tmpl := ts.htmlTemplates.Lookup(templateName)
	if tmpl == nil {
		return "", fmt.Errorf("HTML template '%s' not found", templateName)
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute HTML template '%s': %w", templateName, err)
	}

	return buf.String(), nil
}

// renderText renders a text template
func (ts *TemplateService) renderText(templateName string, data TemplateData) (string, error) {
	tmpl := ts.textTemplates.Lookup(templateName)
	if tmpl == nil {
		return "", fmt.Errorf("text template '%s' not found", templateName)
	}

	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute text template '%s': %w", templateName, err)
	}

	return buf.String(), nil
}

// title converts a string to title case (first letter of each word capitalized)
func title(s string) string {
	if len(s) == 0 {
		return s
	}
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
		}
	}
	return strings.Join(words, " ")
}

// loadHTMLTemplates loads all HTML templates from the embedded filesystem
func loadHTMLTemplates() (*htmltpl.Template, error) {
	templates := htmltpl.New("").Funcs(htmltpl.FuncMap{
		"toUpper": strings.ToUpper,
		"toLower": strings.ToLower,
		"title":   title,
	})

	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if filepath.Ext(filename) != ".html" {
			continue
		}

		content, err := templateFS.ReadFile("templates/" + filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read template file '%s': %w", filename, err)
		}

		templateName := strings.TrimSuffix(filename, ".html")
		_, err = templates.New(templateName).Parse(string(content))
		if err != nil {
			return nil, fmt.Errorf("failed to parse HTML template '%s': %w", filename, err)
		}
	}

	return templates, nil
}

// loadTextTemplates loads all text templates from the embedded filesystem
func loadTextTemplates() (*texttpl.Template, error) {
	templates := texttpl.New("").Funcs(texttpl.FuncMap{
		"toUpper": strings.ToUpper,
		"toLower": strings.ToLower,
		"title":   title,
	})

	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if filepath.Ext(filename) != ".txt" {
			continue
		}

		content, err := templateFS.ReadFile("templates/" + filename)
		if err != nil {
			return nil, fmt.Errorf("failed to read template file '%s': %w", filename, err)
		}

		templateName := strings.TrimSuffix(filename, ".txt")
		_, err = templates.New(templateName).Parse(string(content))
		if err != nil {
			return nil, fmt.Errorf("failed to parse text template '%s': %w", filename, err)
		}
	}

	return templates, nil
}

// ListTemplates returns a list of available template names
func (ts *TemplateService) ListTemplates() []string {
	var templates []string

	for _, tmpl := range ts.htmlTemplates.Templates() {
		if tmpl.Name() != "" {
			templates = append(templates, tmpl.Name())
		}
	}

	return templates
}
