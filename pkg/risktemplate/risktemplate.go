// Package risktemplate holds the dependency-free rules a risk template must satisfy. The
// API's risk template service enforces them when a template is saved, and the policy
// contract checker (pkg/policyeval) applies them to the risk_templates a Rego package
// declares, so a policy can be checked before an agent ever submits its templates. It must
// not import anything that pulls in a database or the API's internals: the agent imports
// it through pkg/policyeval.
package risktemplate

import (
	"slices"
	"strings"
	"text/template"
	"text/template/parse"
)

// Limits on a risk template. The API rejects a template over any of them.
const (
	MaxFieldLength      = 1000 // characters, for every text field
	MaxThreatRefs       = 50
	MaxViolationIDs     = 100
	MaxRemediationTasks = 100
	MaxLabelSchemaItems = 100
	MaxDedupeLabelKeys  = 20
)

// RiskLevels are the values a likelihood or impact hint may take, after NormalizeRiskLevel.
var RiskLevels = []string{"negligible", "low", "moderate", "high", "critical"}

// NormalizeRiskLevel lowercases and trims a risk level and maps the legacy "medium" to
// "moderate".
func NormalizeRiskLevel(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	if normalized == "medium" {
		return "moderate"
	}
	return normalized
}

// IsTemplated reports whether a text field holds a Go template action, which is rendered
// against the risk's labels and so is not checked as a literal value.
func IsTemplated(value string) bool {
	return strings.Contains(value, "{{")
}

// ValidHint reports whether value is an acceptable likelihood or impact hint: empty, a
// template, or a risk level.
func ValidHint(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || IsTemplated(trimmed) {
		return true
	}
	return slices.Contains(RiskLevels, NormalizeRiskLevel(trimmed))
}

// TemplateLabelKeys parses a Go template and returns the label keys it references
// ({{.key}}). Templates are rendered against the risk's labels, so every key must be in
// the template's label schema.
func TemplateLabelKeys(text string) (map[string]struct{}, error) {
	tmpl, err := template.New("validation").Option("missingkey=zero").Parse(text)
	if err != nil {
		return nil, err
	}
	return templateFields(tmpl.Root), nil
}

// templateFields recursively collects the field references in a template parse tree.
func templateFields(node parse.Node) map[string]struct{} {
	fields := make(map[string]struct{})
	add := func(nodes ...parse.Node) {
		for _, n := range nodes {
			for k := range templateFields(n) {
				fields[k] = struct{}{}
			}
		}
	}

	switch n := node.(type) {
	case *parse.ListNode:
		if n != nil {
			add(n.Nodes...)
		}
	case *parse.ActionNode:
		if n != nil && n.Pipe != nil {
			add(n.Pipe)
		}
	case *parse.IfNode:
		if n != nil {
			add(branch(n.BranchNode)...)
		}
	case *parse.RangeNode:
		if n != nil {
			add(branch(n.BranchNode)...)
		}
	case *parse.WithNode:
		if n != nil {
			add(branch(n.BranchNode)...)
		}
	case *parse.PipeNode:
		if n != nil {
			for _, cmd := range n.Cmds {
				add(cmd)
			}
		}
	case *parse.CommandNode:
		if n != nil {
			add(n.Args...)
		}
	case *parse.FieldNode:
		if n != nil && len(n.Ident) > 0 {
			fields[n.Ident[0]] = struct{}{}
		}
	}
	return fields
}

// branch returns the non-nil parts of an if/range/with node.
func branch(b parse.BranchNode) []parse.Node {
	var out []parse.Node
	if b.Pipe != nil {
		out = append(out, b.Pipe)
	}
	if b.List != nil {
		out = append(out, b.List)
	}
	if b.ElseList != nil {
		out = append(out, b.ElseList)
	}
	return out
}
