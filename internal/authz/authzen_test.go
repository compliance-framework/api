package authz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// decodeBody unmarshals the JSON request body the driver sent to the mock PDP.
func decodeBody(t *testing.T, r *http.Request, out any) {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("unmarshal request body %q: %v", string(b), err)
	}
}

func newDriver(t *testing.T, endpoint string) *AuthZen {
	t.Helper()
	d, err := NewAuthZen(endpoint, nil)
	if err != nil {
		t.Fatalf("NewAuthZen(%q) error = %v", endpoint, err)
	}
	return d
}

// TestNewAuthZenValidation locks in fail-fast construction: an empty or malformed endpoint
// is a startup error, and the batch URL is derived by AuthZen convention.
func TestNewAuthZenValidation(t *testing.T) {
	if _, err := NewAuthZen("", nil); err == nil {
		t.Error("NewAuthZen(\"\") error = nil, want error")
	}
	if _, err := NewAuthZen("not-a-url", nil); err == nil {
		t.Error("NewAuthZen(\"not-a-url\") error = nil, want error")
	}
	d := newDriver(t, "https://pdp.internal/access/v1/evaluation")
	if got, want := d.evalsURL, "https://pdp.internal/access/v1/evaluations"; got != want {
		t.Errorf("evalsURL = %q, want %q", got, want)
	}
	if got, want := d.wellKnownURL, "https://pdp.internal/.well-known/authzen-configuration"; got != want {
		t.Errorf("wellKnownURL = %q, want %q", got, want)
	}
	// A non-conventional path reuses the same URL for batch.
	d2 := newDriver(t, "https://pdp.internal/decide")
	if d2.evalsURL != "https://pdp.internal/decide" {
		t.Errorf("evalsURL fallback = %q, want same as eval URL", d2.evalsURL)
	}
	// Near-miss inputs (trailing slash, query string) still derive the batch URL.
	derive := []struct{ in, want string }{
		{"https://pdp.internal/access/v1/evaluation/", "https://pdp.internal/access/v1/evaluations"},
		{"https://pdp.internal/access/v1/evaluation?tenant=x", "https://pdp.internal/access/v1/evaluations?tenant=x"},
	}
	for _, tc := range derive {
		if got := newDriver(t, tc.in).evalsURL; got != tc.want {
			t.Errorf("evalsURL for %q = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEvaluateRequestShapeConformance asserts the wire request matches the AuthZen
// Authorization API: subject{type,id,properties}, action{name}, resource{type,id}, context.
func TestEvaluateRequestShapeConformance(t *testing.T) {
	var got authzenEvaluation
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		decodeBody(t, r, &got)
		_ = json.NewEncoder(w).Encode(authzenDecisionResponse{Decision: true})
	}))
	defer srv.Close()

	d := newDriver(t, srv.URL+"/access/v1/evaluation")
	dec, err := d.Evaluate(context.Background(),
		Subject{Type: "user", ID: "alice@acme.com", Props: map[string]any{"given_name": "Alice"}},
		"read",
		Resource{Type: "evidence", ID: "42"},
		map[string]any{"method": "GET"})
	if err != nil {
		t.Fatalf("Evaluate error = %v", err)
	}
	if !dec.Allow {
		t.Errorf("decision Allow = false, want true")
	}
	if got.Subject.Type != "user" || got.Subject.ID != "alice@acme.com" {
		t.Errorf("subject = %+v, want type=user id=alice@acme.com", got.Subject)
	}
	if got.Subject.Properties["given_name"] != "Alice" {
		t.Errorf("subject.properties.given_name = %v, want Alice", got.Subject.Properties["given_name"])
	}
	if got.Action.Name != "read" {
		t.Errorf("action.name = %q, want read", got.Action.Name)
	}
	if got.Resource.Type != "evidence" || got.Resource.ID != "42" {
		t.Errorf("resource = %+v, want type=evidence id=42", got.Resource)
	}
	if got.Context["method"] != "GET" {
		t.Errorf("context.method = %v, want GET", got.Context["method"])
	}
}

// TestEvaluateDecisionMapping is an AuthZen-interop-style table: the canonical allow/deny
// shapes a compliant PDP returns map to the right CCF Decision, including a reason in the
// response context.
func TestEvaluateDecisionMapping(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantAllow  bool
		wantReason string
	}{
		{"allow", `{"decision":true}`, true, ""},
		{"deny", `{"decision":false}`, false, ""},
		{"deny with reason", `{"decision":false,"context":{"reason":"not an admin"}}`, false, "not an admin"},
		{"allow with extra context", `{"decision":true,"context":{"id":"req-1"}}`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			d := newDriver(t, srv.URL+"/access/v1/evaluation")
			dec, err := d.Evaluate(context.Background(), Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil)
			if err != nil {
				t.Fatalf("Evaluate error = %v", err)
			}
			if dec.Allow != tc.wantAllow {
				t.Errorf("Allow = %v, want %v", dec.Allow, tc.wantAllow)
			}
			if dec.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", dec.Reason, tc.wantReason)
			}
		})
	}
}

// TestEvaluationsBatch verifies the batch path: one HTTP call to the evaluations endpoint,
// requests serialized in order, and decisions mapped back positionally.
func TestEvaluationsBatch(t *testing.T) {
	var calls int
	var got authzenEvaluationsRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.HasSuffix(r.URL.Path, "/evaluations") {
			t.Errorf("batch path = %q, want suffix /evaluations", r.URL.Path)
		}
		decodeBody(t, r, &got)
		_ = json.NewEncoder(w).Encode(authzenEvaluationsResponse{Evaluations: []authzenDecisionResponse{
			{Decision: true}, {Decision: false}, {Decision: true},
		}})
	}))
	defer srv.Close()

	d := newDriver(t, srv.URL+"/access/v1/evaluation")
	reqs := []EvalRequest{
		{Subject: Subject{Type: "user", ID: "a"}, Action: "read", Resource: Resource{Type: "evidence"}},
		{Subject: Subject{Type: "user", ID: "a"}, Action: "delete", Resource: Resource{Type: "evidence"}},
		{Subject: Subject{Type: "user", ID: "a"}, Action: "read", Resource: Resource{Type: "catalog"}},
	}
	decs, err := d.Evaluations(context.Background(), reqs)
	if err != nil {
		t.Fatalf("Evaluations error = %v", err)
	}
	if calls != 1 {
		t.Errorf("HTTP calls = %d, want 1 (batched)", calls)
	}
	if len(got.Evaluations) != 3 {
		t.Fatalf("sent %d evaluations, want 3", len(got.Evaluations))
	}
	if got.Evaluations[1].Action.Name != "delete" {
		t.Errorf("evaluations[1].action = %q, want delete", got.Evaluations[1].Action.Name)
	}
	want := []bool{true, false, true}
	for i, w := range want {
		if decs[i].Allow != w {
			t.Errorf("decisions[%d].Allow = %v, want %v", i, decs[i].Allow, w)
		}
	}
}

func TestEvaluationsEmptyReturnsNoCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("server should not be called for an empty batch")
	}))
	defer srv.Close()
	d := newDriver(t, srv.URL+"/access/v1/evaluation")
	decs, err := d.Evaluations(context.Background(), nil)
	if err != nil || len(decs) != 0 {
		t.Fatalf("Evaluations(nil) = (%v, %v), want ([], nil)", decs, err)
	}
}

func TestEvaluationsLengthMismatchErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// One decision for a two-request batch.
		_ = json.NewEncoder(w).Encode(authzenEvaluationsResponse{Evaluations: []authzenDecisionResponse{{Decision: true}}})
	}))
	defer srv.Close()
	d := newDriver(t, srv.URL+"/access/v1/evaluation")
	_, err := d.Evaluations(context.Background(),
		[]EvalRequest{{Action: "read"}, {Action: "delete"}})
	if err == nil {
		t.Fatal("Evaluations error = nil, want length-mismatch error")
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("length mismatch should not be ErrUnavailable")
	}
}

// TestErrorClassification locks in the fail-mode contract: transport failures, timeouts,
// 5xx and 429 wrap ErrUnavailable (PEP applies fail mode); other 4xx are plain errors
// (PEP → 500).
func TestErrorClassification(t *testing.T) {
	t.Run("5xx is unavailable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer srv.Close()
		d := newDriver(t, srv.URL+"/access/v1/evaluation")
		_, err := d.Evaluate(context.Background(), Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil)
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrUnavailable", err)
		}
	})
	t.Run("429 is unavailable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		d := newDriver(t, srv.URL+"/access/v1/evaluation")
		_, err := d.Evaluate(context.Background(), Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil)
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrUnavailable", err)
		}
	})
	t.Run("400 is a plain error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "bad tuple")
		}))
		defer srv.Close()
		d := newDriver(t, srv.URL+"/access/v1/evaluation")
		_, err := d.Evaluate(context.Background(), Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil)
		if err == nil {
			t.Fatal("err = nil, want error")
		}
		if errors.Is(err, ErrUnavailable) {
			t.Error("400 should not be ErrUnavailable")
		}
	})
	t.Run("transport failure is unavailable", func(t *testing.T) {
		// Point at a closed port: the dial fails.
		d := newDriver(t, "http://127.0.0.1:1/access/v1/evaluation")
		_, err := d.Evaluate(context.Background(), Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil)
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want ErrUnavailable", err)
		}
	})
}

// TestContextDeadlineHonored proves the caller's context cancels an in-flight PDP call,
// surfaced as ErrUnavailable.
func TestContextDeadlineHonored(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // block until the test releases, after the context has expired
		_ = json.NewEncoder(w).Encode(authzenDecisionResponse{Decision: true})
	}))
	defer srv.Close()
	defer close(release)

	d := newDriver(t, srv.URL+"/access/v1/evaluation")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := d.Evaluate(ctx, Subject{Type: "user", ID: "a"}, "read", Resource{Type: "evidence"}, nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable on context deadline", err)
	}
}

// TestHealth checks the readiness probe against the AuthZen well-known metadata endpoint.
func TestHealth(t *testing.T) {
	var path string
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	d := newDriver(t, healthy.URL+"/access/v1/evaluation")
	if err := d.Health(context.Background()); err != nil {
		t.Errorf("Health error = %v, want nil", err)
	}
	if path != "/.well-known/authzen-configuration" {
		t.Errorf("health probed %q, want /.well-known/authzen-configuration", path)
	}

	down := newDriver(t, "http://127.0.0.1:1/access/v1/evaluation")
	if err := down.Health(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Health(down) err = %v, want ErrUnavailable", err)
	}
}

// TestDriverRegistered confirms the authzen driver self-registers and Open builds it from
// config (and that a missing endpoint fails fast).
func TestDriverRegistered(t *testing.T) {
	found := false
	for _, name := range Drivers() {
		if name == DriverAuthzen {
			found = true
		}
	}
	if !found {
		t.Fatalf("Drivers() = %v, missing %q", Drivers(), DriverAuthzen)
	}
	if _, err := Open(Options{Driver: DriverAuthzen}, Deps{}); err == nil {
		t.Error("Open(authzen) with no endpoint = nil error, want failure")
	}
	if _, err := Open(Options{Driver: DriverAuthzen, Endpoint: "https://pdp.internal/access/v1/evaluation"}, Deps{}); err != nil {
		t.Errorf("Open(authzen) with endpoint error = %v", err)
	}
}
