package templates

import (
	"bytes"
	"fmt"
	"text/template"
	"text/template/parse"
)

// renderTemplate executes a Go template string with the provided label data.
// Returns the rendered string or an error if the template is invalid or execution fails.
func renderTemplate(tmplStr string, labels map[string]string) (string, error) {
	if tmplStr == "" {
		return "", nil
	}

	tmpl, err := template.New("field").Parse(tmplStr)
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
func validateTemplateAgainstSchema(tmplStr string, labelSchema []SubjectTemplateLabelSchemaField) error {
	if tmplStr == "" {
		return nil
	}

	// Parse the template to extract variable references
	tmpl, err := template.New("validation").Parse(tmplStr)
	if err != nil {
		return fmt.Errorf("invalid template syntax: %w", err)
	}

	// Build a map of valid keys from the schema
	validKeys := make(map[string]struct{})
	for _, field := range labelSchema {
		validKeys[field.Key] = struct{}{}
	}

	// Extract field references from the template tree
	referencedKeys := extractTemplateFields(tmpl.Tree.Root)

	// Check if all referenced keys are in the schema
	for key := range referencedKeys {
		if _, valid := validKeys[key]; !valid {
			return fmt.Errorf("template references undefined label key: %q (not in label schema)", key)
		}
	}

	return nil
}

// extractTemplateFields recursively extracts field references from a template parse tree
func extractTemplateFields(node parse.Node) map[string]struct{} {
	fields := make(map[string]struct{})

	if node == nil {
		return fields
	}

	switch n := node.(type) {
	case *parse.ListNode:
		if n != nil {
			for _, child := range n.Nodes {
				for k := range extractTemplateFields(child) {
					fields[k] = struct{}{}
				}
			}
		}
	case *parse.ActionNode:
		if n != nil && n.Pipe != nil {
			for k := range extractTemplateFields(n.Pipe) {
				fields[k] = struct{}{}
			}
		}
	case *parse.IfNode:
		if n != nil {
			for k := range extractTemplateFields(n.Pipe) {
				fields[k] = struct{}{}
			}
			for k := range extractTemplateFields(n.List) {
				fields[k] = struct{}{}
			}
			for k := range extractTemplateFields(n.ElseList) {
				fields[k] = struct{}{}
			}
		}
	case *parse.RangeNode:
		if n != nil {
			for k := range extractTemplateFields(n.Pipe) {
				fields[k] = struct{}{}
			}
			for k := range extractTemplateFields(n.List) {
				fields[k] = struct{}{}
			}
			for k := range extractTemplateFields(n.ElseList) {
				fields[k] = struct{}{}
			}
		}
	case *parse.WithNode:
		if n != nil {
			for k := range extractTemplateFields(n.Pipe) {
				fields[k] = struct{}{}
			}
			for k := range extractTemplateFields(n.List) {
				fields[k] = struct{}{}
			}
			for k := range extractTemplateFields(n.ElseList) {
				fields[k] = struct{}{}
			}
		}
	case *parse.PipeNode:
		if n != nil {
			for _, cmd := range n.Cmds {
				for k := range extractTemplateFields(cmd) {
					fields[k] = struct{}{}
				}
			}
		}
	case *parse.CommandNode:
		if n != nil {
			for _, arg := range n.Args {
				for k := range extractTemplateFields(arg) {
					fields[k] = struct{}{}
				}
			}
		}
	case *parse.FieldNode:
		if n != nil && len(n.Ident) > 0 {
			// Field access like {{.fieldName}}
			fields[n.Ident[0]] = struct{}{}
		}
	}

	return fields
}
