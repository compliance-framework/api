package suggestions

import (
	"bytes"
	"encoding/json"
	"text/template"
)

const PromptVersion = "v2"

const SystemPrompt = `You map compliance evidence streams to security controls for a specific SSP.

You are given:
1. The system context: name, description, components it uses, plus each control's implementation text from this plan.
2. A subset of the controls in this SSP.
3. A subset of evidence label-sets with sample titles.
4. Label-key documentation.
5. The dashboards visible to this plan.

The controls and label-sets shown are one slice of a larger set. Only map what you see; absence here means nothing.

For each shown control that a shown label-set provides evidence for, emit a mapping, but only when the evidence pertains to this system. When a label identifies an asset such as a repository, cluster, account, host, service, image, namespace, project, or environment, that asset must correspond to a component or description in the system context. Exclude evidence for assets this system does not use.

Respect qualifiers in the control text. A control scoped to a provider, technology, component, environment, or other qualifier only matches evidence whose labels satisfy that qualifier.

For every mapping, include proposed_filter_labels as a list of {"key","value"} pairs: the smallest label subset that the dashboard filter should use. Choose labels that capture the control's evidence intent and generalize to future components. Always include _policy when present. Do not include _agent or _plugin because they describe collection mechanics, not the evidence. Avoid instance identity labels such as repository, organization, account, host, namespace, project, or environment unless the control or system context is clearly scoped to that specific instance.

Use extend_filter with target_filter_id only when one of this plan's own dashboards has exactly the same proposed_filter_labels. Otherwise use new_filter with a short descriptive proposed_filter_name. Global dashboards are listed only to avoid duplicate names; never extend them.

Only reference control_key and label_set_hash values present in the input, and only choose proposed_filter_labels from labels present on that evidence label-set. Reasoning must state both why the evidence satisfies the control and why it belongs to this system. Provide confidence from 0 to 1.`

func OutputSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []any{"mappings"},
		"properties": map[string]any{
			"mappings": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []any{"control_key", "label_set_hash", "action", "proposed_filter_labels", "confidence", "reasoning"},
					"properties": map[string]any{
						"control_key": map[string]any{
							"type": "string",
						},
						"label_set_hash": map[string]any{
							"type": "string",
						},
						"action": map[string]any{
							"type": "string",
							"enum": []any{MappingActionNewFilter, MappingActionExtendFilter},
						},
						"target_filter_id": map[string]any{
							"type": "string",
						},
						"proposed_filter_name": map[string]any{
							"type": "string",
						},
						"proposed_filter_labels": map[string]any{
							"type": "array",
							"items": map[string]any{
								"type":                 "object",
								"additionalProperties": false,
								"required":             []any{"key", "value"},
								"properties": map[string]any{
									"key": map[string]any{
										"type": "string",
									},
									"value": map[string]any{
										"type": "string",
									},
								},
							},
						},
						"confidence": map[string]any{
							"type": "number",
						},
						"reasoning": map[string]any{
							"type": "string",
						},
					},
				},
			},
		},
	}
}

// The prompt is split into three segments so the request can place prompt-cache
// breakpoints at the boundaries:
//
//	System   — the instructions plus run-stable context (system context,
//	           label-key docs, dashboards). Identical for every cell of an SSP.
//	Controls — the control chunk for this cell. Identical across the label-set
//	           cells that share a control-row, and the token-heavy dimension.
//	Volatile — the per-cell evidence label-sets and the closing instruction.
//
// Keeping the volatile content last means the System and Controls prefixes are
// byte-stable and therefore cacheable.
const systemBlockTemplate = `{{.SystemPrompt}}

Prompt version: {{.PromptVersion}}

System context:
{{json .Input.SystemContext}}

Label-key documentation:
{{json .Input.LabelKeyDocs}}

This SSP's extendable dashboards:
{{json .Input.SameSSPFilters}}

Global dashboard names:
{{json .Input.GlobalFilterNames}}{{if .ConstraintsText}}

Generation constraints (the user has scoped this run; honour every constraint):
{{.ConstraintsText}}{{end}}`

const controlsBlockTemplate = `Controls:
{{json .Input.Controls}}`

const volatileBlockTemplate = `Evidence label-sets:
{{json .Input.LabelSets}}

Return JSON matching the provided schema.`

// RenderedPrompt holds the cacheable system/controls prefixes and the volatile
// tail for a single cell.
type RenderedPrompt struct {
	System   string
	Controls string
	Volatile string
}

func renderPromptTemplate(name, text string, input GatheredInput) (string, error) {
	tmpl, err := template.New(name).Funcs(template.FuncMap{
		"json": func(value any) (string, error) {
			raw, err := json.MarshalIndent(value, "", "  ")
			if err != nil {
				return "", err
			}
			return string(raw), nil
		},
	}).Parse(text)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"SystemPrompt":    SystemPrompt,
		"PromptVersion":   PromptVersion,
		"Input":           input,
		"ConstraintsText": describeConstraints(input.Constraints),
	})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func RenderPrompt(input GatheredInput) (RenderedPrompt, error) {
	system, err := renderPromptTemplate("dashboard-suggestion-system", systemBlockTemplate, input)
	if err != nil {
		return RenderedPrompt{}, err
	}
	controls, err := renderPromptTemplate("dashboard-suggestion-controls", controlsBlockTemplate, input)
	if err != nil {
		return RenderedPrompt{}, err
	}
	volatile, err := renderPromptTemplate("dashboard-suggestion-volatile", volatileBlockTemplate, input)
	if err != nil {
		return RenderedPrompt{}, err
	}
	return RenderedPrompt{System: system, Controls: controls, Volatile: volatile}, nil
}
