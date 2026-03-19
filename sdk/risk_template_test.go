package sdk

import (
	"encoding/json"
	"testing"

	"github.com/compliance-framework/api/sdk/types"
)

func TestUpsertRiskTemplatesRequestMarshalPreservesZeroOrderIndex(t *testing.T) {
	reqData := upsertRiskTemplatesRequest{
		PluginID:      "plugin-a",
		PolicyPackage: "package-a",
		Templates: []types.RiskTemplate{
			{
				Name: "template-a",
				Remediation: &types.Remediation{
					Title: "Fix it",
					Tasks: []types.RemediationTask{
						{Title: "First task", OrderIndex: 0},
						{Title: "Second task", OrderIndex: 1},
					},
				},
			},
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	templates, ok := payload["templates"].([]any)
	if !ok || len(templates) != 1 {
		t.Fatalf("expected 1 template in payload, got %#v", payload["templates"])
	}

	template, ok := templates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected template object, got %#v", templates[0])
	}

	remediation, ok := template["remediation-template"].(map[string]any)
	if !ok {
		t.Fatalf("expected remediation-template object, got %#v", template["remediation-template"])
	}

	tasks, ok := remediation["tasks"].([]any)
	if !ok || len(tasks) != 2 {
		t.Fatalf("expected 2 remediation tasks, got %#v", remediation["tasks"])
	}

	firstTask, ok := tasks[0].(map[string]any)
	if !ok {
		t.Fatalf("expected task object, got %#v", tasks[0])
	}

	if got, exists := firstTask["order-index"]; !exists || got != float64(0) {
		t.Fatalf("expected first task order-index to be present and equal 0, got present=%t value=%#v", exists, got)
	}
}

func TestUpsertRiskTemplatesRequestMarshalOmitsUnsetIsActive(t *testing.T) {
	reqData := upsertRiskTemplatesRequest{
		PluginID:      "plugin-a",
		PolicyPackage: "package-a",
		Templates: []types.RiskTemplate{
			{
				ID:        "template-a",
				Name:      "template-a",
				Title:     "Template A",
				Statement: "Template statement",
			},
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	templates, ok := payload["templates"].([]any)
	if !ok || len(templates) != 1 {
		t.Fatalf("expected 1 template in payload, got %#v", payload["templates"])
	}

	template, ok := templates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected template object, got %#v", templates[0])
	}

	if got, exists := template["is-active"]; exists {
		t.Fatalf("expected is-active to be omitted when unset, got value=%#v", got)
	}
}

func TestUpsertRiskTemplatesRequestMarshalIncludesExplicitFalseIsActive(t *testing.T) {
	reqData := upsertRiskTemplatesRequest{
		PluginID:      "plugin-a",
		PolicyPackage: "package-a",
		Templates: []types.RiskTemplate{
			{
				ID:        "template-a",
				Name:      "template-a",
				Title:     "Template A",
				Statement: "Template statement",
				IsActive:  boolPtr(false),
			},
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	templates, ok := payload["templates"].([]any)
	if !ok || len(templates) != 1 {
		t.Fatalf("expected 1 template in payload, got %#v", payload["templates"])
	}

	template, ok := templates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected template object, got %#v", templates[0])
	}

	if got, exists := template["is-active"]; !exists || got != false {
		t.Fatalf("expected is-active to be present and false, got present=%t value=%#v", exists, got)
	}
}

func TestUpsertRiskTemplatesRequestMarshalOmitsUnsetOptionalFields(t *testing.T) {
	reqData := upsertRiskTemplatesRequest{
		PluginID:      "plugin-a",
		PolicyPackage: "package-a",
		Templates: []types.RiskTemplate{
			{
				ID:        "template-a",
				Name:      "template-a",
				Title:     "Template A",
				Statement: "Template statement",
				Threats: []types.Threat{
					{
						System:     "https://cwe.mitre.org",
						ExternalID: "CWE-312",
						Title:      "Cleartext Storage",
					},
				},
			},
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	templates, ok := payload["templates"].([]any)
	if !ok || len(templates) != 1 {
		t.Fatalf("expected 1 template in payload, got %#v", payload["templates"])
	}

	template, ok := templates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected template object, got %#v", templates[0])
	}

	if got, exists := template["likelihood-hint"]; exists {
		t.Fatalf("expected likelihood-hint to be omitted when unset, got value=%#v", got)
	}
	if got, exists := template["impact-hint"]; exists {
		t.Fatalf("expected impact-hint to be omitted when unset, got value=%#v", got)
	}

	threats, ok := template["threat-ids"].([]any)
	if !ok || len(threats) != 1 {
		t.Fatalf("expected 1 threat in payload, got %#v", template["threat-ids"])
	}

	threat, ok := threats[0].(map[string]any)
	if !ok {
		t.Fatalf("expected threat object, got %#v", threats[0])
	}

	if got, exists := threat["url"]; exists {
		t.Fatalf("expected threat url to be omitted when unset, got value=%#v", got)
	}
}

func TestUpsertRiskTemplatesRequestMarshalIncludesExplicitOptionalFields(t *testing.T) {
	reqData := upsertRiskTemplatesRequest{
		PluginID:      "plugin-a",
		PolicyPackage: "package-a",
		Templates: []types.RiskTemplate{
			{
				ID:             "template-a",
				Name:           "template-a",
				Title:          "Template A",
				Statement:      "Template statement",
				LikelihoodHint: stringPtr("medium"),
				ImpactHint:     stringPtr("high"),
				Threats: []types.Threat{
					{
						System:     "https://cwe.mitre.org",
						ExternalID: "CWE-312",
						Title:      "Cleartext Storage",
						Url:        stringPtr("https://cwe.mitre.org/data/definitions/312.html"),
					},
				},
			},
		},
	}

	reqBody, err := json.Marshal(reqData)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}

	templates, ok := payload["templates"].([]any)
	if !ok || len(templates) != 1 {
		t.Fatalf("expected 1 template in payload, got %#v", payload["templates"])
	}

	template, ok := templates[0].(map[string]any)
	if !ok {
		t.Fatalf("expected template object, got %#v", templates[0])
	}

	if got, exists := template["likelihood-hint"]; !exists || got != "medium" {
		t.Fatalf("expected likelihood-hint to be present and equal medium, got present=%t value=%#v", exists, got)
	}
	if got, exists := template["impact-hint"]; !exists || got != "high" {
		t.Fatalf("expected impact-hint to be present and equal high, got present=%t value=%#v", exists, got)
	}

	threats, ok := template["threat-ids"].([]any)
	if !ok || len(threats) != 1 {
		t.Fatalf("expected 1 threat in payload, got %#v", template["threat-ids"])
	}

	threat, ok := threats[0].(map[string]any)
	if !ok {
		t.Fatalf("expected threat object, got %#v", threats[0])
	}

	if got, exists := threat["url"]; !exists || got != "https://cwe.mitre.org/data/definitions/312.html" {
		t.Fatalf("expected threat url to be present and equal request value, got present=%t value=%#v", exists, got)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func stringPtr(v string) *string {
	return &v
}
