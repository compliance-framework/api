package sdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/compliance-framework/api/sdk/types"
)

func newRiskTemplateTestClient(handler roundTripFunc) *Client {
	return NewClient(&http.Client{Transport: handler}, &Config{BaseURL: "http://example.test"})
}

func TestRiskTemplateUpsertPostsBatchPayload(t *testing.T) {
	var (
		gotMethod      string
		gotPath        string
		gotContentType string
		gotRequest     upsertRiskTemplatesRequest
	)

	client := newRiskTemplateTestClient(func(r *http.Request) (*http.Response, error) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		if err := json.Unmarshal(body, &gotRequest); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	err := client.RiskTemplate.Upsert(context.Background(), "plugin-a", "package-a", types.RiskTemplate{
		ID:        "template-a",
		Name:      "Template A",
		Title:     "Template A",
		Statement: "Template statement",
	})
	if err != nil {
		t.Fatalf("upsert risk templates: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("expected method %q, got %q", http.MethodPost, gotMethod)
	}
	if gotPath != "/api/agent/risk-templates/batch" {
		t.Fatalf("expected path %q, got %q", "/api/agent/risk-templates/batch", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected content type %q, got %q", "application/json", gotContentType)
	}
	if gotRequest.PluginID != "plugin-a" {
		t.Fatalf("expected plugin-id %q, got %q", "plugin-a", gotRequest.PluginID)
	}
	if gotRequest.PolicyPackage != "package-a" {
		t.Fatalf("expected policy-package %q, got %q", "package-a", gotRequest.PolicyPackage)
	}
	if len(gotRequest.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(gotRequest.Templates))
	}
	if gotRequest.Templates[0].ID != "template-a" {
		t.Fatalf("expected template id %q, got %q", "template-a", gotRequest.Templates[0].ID)
	}
}

func TestRiskTemplateUpsertSendsExplicitEmptyTemplateList(t *testing.T) {
	var gotRequest upsertRiskTemplatesRequest

	client := newRiskTemplateTestClient(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		if err := json.Unmarshal(body, &gotRequest); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	err := client.RiskTemplate.Upsert(context.Background(), "plugin-a", "package-a")
	if err != nil {
		t.Fatalf("upsert empty risk templates: %v", err)
	}

	if gotRequest.PluginID != "plugin-a" {
		t.Fatalf("expected plugin-id %q, got %q", "plugin-a", gotRequest.PluginID)
	}
	if gotRequest.PolicyPackage != "package-a" {
		t.Fatalf("expected policy-package %q, got %q", "package-a", gotRequest.PolicyPackage)
	}
	if gotRequest.Templates == nil {
		t.Fatal("expected templates to be encoded as an empty array, got nil")
	}
	if len(gotRequest.Templates) != 0 {
		t.Fatalf("expected 0 templates, got %d", len(gotRequest.Templates))
	}
}

func TestRiskTemplateUpsertAcceptsCreatedStatus(t *testing.T) {
	client := newRiskTemplateTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	err := client.RiskTemplate.Upsert(context.Background(), "plugin-a", "package-a", types.RiskTemplate{
		ID:        "template-a",
		Name:      "Template A",
		Title:     "Template A",
		Statement: "Template statement",
	})
	if err != nil {
		t.Fatalf("expected http 201 to succeed, got %v", err)
	}
}

func TestRiskTemplateUpsertReturnsErrorOnUnexpectedStatus(t *testing.T) {
	client := newRiskTemplateTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	err := client.RiskTemplate.Upsert(context.Background(), "plugin-a", "package-a", types.RiskTemplate{
		ID:        "template-a",
		Name:      "Template A",
		Title:     "Template A",
		Statement: "Template statement",
	})
	if err == nil {
		t.Fatal("expected error for unexpected status code")
	}
	if !strings.Contains(err.Error(), "418") {
		t.Fatalf("expected error to mention status code 418, got %q", err.Error())
	}
}

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
				ThreatRefs: []types.ThreatRef{
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
				ThreatRefs: []types.ThreatRef{
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
