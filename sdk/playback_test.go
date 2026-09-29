package sdk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/compliance-framework/api/pkg/policyeval"
)

func playbackTestClient(t *testing.T, status int, body string, gotBody *string) *Client {
	t.Helper()
	return NewClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/playback/evaluate" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if gotBody != nil {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			*gotBody = string(b)
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})}, &Config{BaseURL: "http://example.test"})
}

func TestPlaybackEvaluateReturnsResults(t *testing.T) {
	var gotBody string
	client := playbackTestClient(t, http.StatusOK,
		`{"results":[{"package":"compliance_framework.x","file":"policy.rego","status":"satisfied"}],"prints":[],"durationMs":3}`,
		&gotBody)

	resp, err := client.Playback.Evaluate(context.Background(), PlaybackRequest{
		Policy: "package compliance_framework.x",
		Input:  map[string]any{"a": 1},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].Status != policyeval.StatusSatisfied {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !strings.Contains(gotBody, `"policy":"package compliance_framework.x"`) || !strings.Contains(gotBody, `"input":{"a":1}`) {
		t.Fatalf("unexpected request body: %s", gotBody)
	}
}

func TestPlaybackEvaluateReturnsPolicyErrors(t *testing.T) {
	client := playbackTestClient(t, http.StatusUnprocessableEntity,
		`{"errors":[{"code":"rego_parse_error","message":"unexpected eof token","file":"policy.rego","row":3,"col":8}]}`,
		nil)

	_, err := client.Playback.Evaluate(context.Background(), PlaybackRequest{Policy: "package x", Input: map[string]any{}})

	var policyErr *PlaybackPolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("expected *PlaybackPolicyError, got %T: %v", err, err)
	}
	if len(policyErr.Errors) != 1 || policyErr.Errors[0].Code != "rego_parse_error" || policyErr.Errors[0].Row != 3 {
		t.Fatalf("unexpected policy errors: %+v", policyErr.Errors)
	}
}

func TestPlaybackEvaluateReturnsStatusErrors(t *testing.T) {
	client := playbackTestClient(t, http.StatusTooManyRequests, `{"errors":{"body":"busy"}}`, nil)

	_, err := client.Playback.Evaluate(context.Background(), PlaybackRequest{Policy: "package x", Input: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected a 429 error, got %v", err)
	}
}
