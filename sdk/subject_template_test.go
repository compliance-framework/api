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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newSubjectTemplateTestClient(handler roundTripFunc) *Client {
	return NewClient(&http.Client{Transport: handler}, &Config{BaseURL: "http://example.test"})
}

func TestSubjectTemplateUpsertPostsBatchPayload(t *testing.T) {
	var (
		gotMethod      string
		gotPath        string
		gotContentType string
		gotRequest     upsertSubjectTemplatesRequest
	)

	client := newSubjectTemplateTestClient(func(r *http.Request) (*http.Response, error) {
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

	err := client.SubjectTemplate.Upsert(context.Background(), "plugin-a", types.SubjectTemplate{
		ID:                  "template-a",
		Name:                "Template A",
		Type:                "component",
		TitleTemplate:       "{{ .asset_id }}",
		DescriptionTemplate: "Asset {{ .asset_id }}",
		PurposeTemplate:     "Track {{ .asset_id }}",
		RemarksTemplate:     "Remark {{ .asset_id }}",
		IdentityLabelKeys:   []string{"asset_id"},
		Props: []types.SubjectProp{
			{Name: "provider", Value: "aws"},
		},
		Links: []types.SubjectLink{
			{Href: "https://example.com/assets/template-a"},
		},
		SourceMode: "runtime-derived",
		SelectorLabels: []types.SubjectTemplateSelectorLabel{
			{Key: "_plugin", Value: "plugin-a"},
			{Key: "environment", Value: "prod"},
		},
		LabelSchema: []types.SubjectTemplateLabelSchema{
			{Key: "asset_id", Description: "Unique asset ID"},
		},
	})
	if err != nil {
		t.Fatalf("upsert subject templates: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("expected method %q, got %q", http.MethodPost, gotMethod)
	}
	if gotPath != "/api/agent/subject-templates/batch" {
		t.Fatalf("expected path %q, got %q", "/api/agent/subject-templates/batch", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected content type %q, got %q", "application/json", gotContentType)
	}
	if gotRequest.PluginId != "plugin-a" {
		t.Fatalf("expected plugin-id %q, got %q", "plugin-a", gotRequest.PluginId)
	}
	if len(gotRequest.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(gotRequest.Templates))
	}

	template := gotRequest.Templates[0]
	if template.ID != "template-a" {
		t.Fatalf("expected template id %q, got %q", "template-a", template.ID)
	}
	if template.SourceMode != "runtime-derived" {
		t.Fatalf("expected source-mode %q, got %q", "runtime-derived", template.SourceMode)
	}
	if len(template.SelectorLabels) != 2 {
		t.Fatalf("expected 2 selector labels, got %d", len(template.SelectorLabels))
	}
	if len(template.LabelSchema) != 1 {
		t.Fatalf("expected 1 label schema field, got %d", len(template.LabelSchema))
	}
	if len(template.Props) != 1 || template.Props[0].Name != "provider" || template.Props[0].Value != "aws" {
		t.Fatalf("expected props to round-trip, got %#v", template.Props)
	}
	if len(template.Links) != 1 || template.Links[0].Href != "https://example.com/assets/template-a" {
		t.Fatalf("expected links to round-trip, got %#v", template.Links)
	}
}

func TestSubjectTemplateUpsertSendsExplicitEmptyTemplateList(t *testing.T) {
	var gotRequest upsertSubjectTemplatesRequest

	client := newSubjectTemplateTestClient(func(r *http.Request) (*http.Response, error) {
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

	err := client.SubjectTemplate.Upsert(context.Background(), "plugin-a")
	if err != nil {
		t.Fatalf("upsert empty subject templates: %v", err)
	}

	if gotRequest.PluginId != "plugin-a" {
		t.Fatalf("expected plugin-id %q, got %q", "plugin-a", gotRequest.PluginId)
	}
	if gotRequest.Templates == nil {
		t.Fatal("expected templates to be encoded as an empty array, got nil")
	}
	if len(gotRequest.Templates) != 0 {
		t.Fatalf("expected 0 templates, got %d", len(gotRequest.Templates))
	}
}

func TestSubjectTemplateUpsertAcceptsCreatedStatus(t *testing.T) {
	client := newSubjectTemplateTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	err := client.SubjectTemplate.Upsert(context.Background(), "plugin-a", types.SubjectTemplate{
		ID:         "template-a",
		Name:       "Template A",
		Type:       "component",
		SourceMode: "runtime-derived",
	})
	if err != nil {
		t.Fatalf("expected http 201 to succeed, got %v", err)
	}
}

func TestSubjectTemplateUpsertReturnsErrorOnUnexpectedStatus(t *testing.T) {
	client := newSubjectTemplateTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})

	err := client.SubjectTemplate.Upsert(context.Background(), "plugin-a", types.SubjectTemplate{
		ID:         "template-a",
		Name:       "Template A",
		Type:       "component",
		SourceMode: "runtime-derived",
	})
	if err == nil {
		t.Fatal("expected error for unexpected status code")
	}
	if !strings.Contains(err.Error(), "418") {
		t.Fatalf("expected error to mention status code 418, got %q", err.Error())
	}
}
