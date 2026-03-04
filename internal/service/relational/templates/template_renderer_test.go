package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  string
		labels    map[string]string
		expected  string
		expectErr bool
	}{
		{
			name:     "simple variable substitution",
			template: "Hello {{.name}}",
			labels:   map[string]string{"name": "World"},
			expected: "Hello World",
		},
		{
			name:     "multiple variables",
			template: "{{.service}} in {{.cluster}}",
			labels:   map[string]string{"service": "api", "cluster": "prod"},
			expected: "api in prod",
		},
		{
			name:     "empty template",
			template: "",
			labels:   map[string]string{"foo": "bar"},
			expected: "",
		},
		{
			name:     "missing variable uses empty string",
			template: "Service: {{.service}}",
			labels:   map[string]string{},
			expected: "Service: <no value>",
		},
		{
			name:      "invalid template syntax",
			template:  "{{.name",
			labels:    map[string]string{"name": "test"},
			expectErr: true,
		},
		{
			name:     "complex template with conditionals",
			template: "{{if .env}}Environment: {{.env}}{{end}}",
			labels:   map[string]string{"env": "production"},
			expected: "Environment: production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := renderTemplate(tt.template, tt.labels)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestValidateTemplateAgainstSchema(t *testing.T) {
	schema := []SubjectTemplateLabelSchemaField{
		{Key: "asset_id"},
		{Key: "cluster"},
		{Key: "namespace"},
	}

	tests := []struct {
		name      string
		template  string
		expectErr bool
	}{
		{
			name:     "valid template with schema keys",
			template: "{{.asset_id}} in {{.cluster}}",
		},
		{
			name:     "empty template is valid",
			template: "",
		},
		{
			name:     "template with all schema keys",
			template: "{{.asset_id}}-{{.cluster}}-{{.namespace}}",
		},
		{
			name:      "invalid template syntax",
			template:  "{{.asset_id",
			expectErr: true,
		},
		{
			name:      "template referencing unexisting keys",
			template:  "{{.foo}} in {{.cluster}}",
			expectErr: true,
		},
		{
			name:     "template with conditionals",
			template: "{{if .cluster}}Cluster: {{.cluster}}{{end}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTemplateAgainstSchema(tt.template, schema)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
