package sdk

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
)

func TestHeartbeatCreatePostsPayload(t *testing.T) {
	var (
		gotMethod      string
		gotPath        string
		gotContentType string
		gotBody        string
	)

	client := NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		gotBody = string(body)

		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}, &Config{BaseURL: "http://example.test"})

	err := client.Heartbeat.Create(context.Background(), types.Heartbeat{
		UUID:      uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		CreatedAt: time.Date(2026, time.April, 7, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("create heartbeat: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("expected method %q, got %q", http.MethodPost, gotMethod)
	}
	if gotPath != "/api/agent/heartbeat" {
		t.Fatalf("expected path %q, got %q", "/api/agent/heartbeat", gotPath)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected content type %q, got %q", "application/json", gotContentType)
	}
	if !strings.Contains(gotBody, "\"uuid\":\"11111111-1111-1111-1111-111111111111\"") {
		t.Fatalf("expected uuid in heartbeat payload, got %q", gotBody)
	}
	if !strings.Contains(gotBody, "\"created_at\":\"2026-04-07T12:00:00Z\"") {
		t.Fatalf("expected created_at in heartbeat payload, got %q", gotBody)
	}
}

func TestHeartbeatCreateReturnsErrorOnUnexpectedStatus(t *testing.T) {
	client := NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTeapot,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}, &Config{BaseURL: "http://example.test"})

	err := client.Heartbeat.Create(context.Background(), types.Heartbeat{
		UUID:      uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		CreatedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected error for unexpected status code")
	}
	if !strings.Contains(err.Error(), "418") {
		t.Fatalf("expected error to mention status code 418, got %q", err.Error())
	}
}
