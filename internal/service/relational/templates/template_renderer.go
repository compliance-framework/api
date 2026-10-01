package templates

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/compliance-framework/api/pkg/risktemplate"
)

// RenderTemplate executes a Go template string with the provided label data.
func RenderTemplate(tmplStr string, labels map[string]string) (string, error) {
	return renderTemplate(tmplStr, labels)
}

// renderTemplate executes a Go template string with the provided label data.
// Returns the rendered string or an error if the template is invalid or execution fails.
func renderTemplate(tmplStr string, labels map[string]string) (string, error) {
	if tmplStr == "" {
		return "", nil
	}

	tmpl, err := template.New("field").Option("missingkey=zero").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("invalid template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, labels); err != nil {
		return "", fmt.Errorf("template execution failed: %w", err)
	}

	return buf.String(), nil
}

// validateTemplateAgainstSchema validates that all template variables reference keys in the label schema.
// Returns an error if the template references undefined keys.
func validateTemplateAgainstSchema(tmplStr *string, labelSchema []SubjectTemplateLabelSchemaField) error {
	if tmplStr == nil || *tmplStr == "" {
		return nil
	}

	// Parse the template to extract variable references
	referencedKeys, err := risktemplate.TemplateLabelKeys(*tmplStr)
	if err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}

	// Build a map of valid keys from the schema
	validKeys := make(map[string]struct{})
	for _, field := range labelSchema {
		validKeys[field.Key] = struct{}{}
	}

	// Check if all referenced keys are in the schema
	for key := range referencedKeys {
		if _, valid := validKeys[key]; !valid {
			return fmt.Errorf("template references undefined label key: %q (not in label schema)", key)
		}
	}

	return nil
}
