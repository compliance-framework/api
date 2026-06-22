package authz

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// These tests assert the authzen driver is wire-compatible with the OpenID AuthZen
// Authorization API as exercised by the interop suite. CCF ships the AuthZen *client* (the
// PEP, BCH-1315), not a PDP, so "conformance" here means three things: the request bodies
// the driver emits match the spec's documented shapes field-for-field; the documented
// response shapes parse; and the canonical interop "Todo" decision scenario round-trips
// correctly through both the single and batch (Evaluations) paths.

// captureBody runs a PDP that records the first decoded JSON request body and replies with
// the given literal response.
func captureBody(t *testing.T, reply string) (*httptest.Server, *map[string]any) {
	t.Helper()
	captured := new(map[string]any)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("unmarshal body %q: %v", string(b), err)
		}
		*captured = m
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply)
	}))
	return srv, captured
}

// TestAuthZenConformance_EvaluationRequestShape pins the single Access Evaluation request
// body to the AuthZen spec shape: subject{type,id[,properties]}, action{name[,properties]},
// resource{type,id[,properties]}, context. With no props the optional objects are omitted.
func TestAuthZenConformance_EvaluationRequestShape(t *testing.T) {
	srv, got := captureBody(t, `{"decision":true}`)
	defer srv.Close()
	d := newDriver(t, srv.URL+"/access/v1/evaluation")

	if _, err := d.Evaluate(context.Background(),
		Subject{Type: "user", ID: "alice@acmecorp.com"},
		"can_read",
		Resource{Type: "todo", ID: "1"},
		map[string]any{"time": "2024-05-31T15:22:06Z"},
	); err != nil {
		t.Fatalf("Evaluate error = %v", err)
	}

	want := map[string]any{
		"subject":  map[string]any{"type": "user", "id": "alice@acmecorp.com"},
		"action":   map[string]any{"name": "can_read"},
		"resource": map[string]any{"type": "todo", "id": "1"},
		"context":  map[string]any{"time": "2024-05-31T15:22:06Z"},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("evaluation request body =\n%#v\nwant\n%#v", *got, want)
	}
}

// TestAuthZenConformance_EvaluationRequestPropertiesShape confirms subject/resource
// attributes are carried under the spec's `properties` key — this is the push channel the
// design (BCH-1319 §8) relies on for C1/C2 attributes; the driver must transport whatever
// the PIP places in the tuple verbatim.
func TestAuthZenConformance_EvaluationRequestPropertiesShape(t *testing.T) {
	srv, got := captureBody(t, `{"decision":true}`)
	defer srv.Close()
	d := newDriver(t, srv.URL+"/access/v1/evaluation")

	if _, err := d.Evaluate(context.Background(),
		Subject{Type: "user", ID: "alice@acmecorp.com", Props: map[string]any{"groups": []any{"payments"}}},
		"can_update",
		Resource{Type: "evidence", ID: "42", Props: map[string]any{"labels": map[string]any{"team": "payments"}}},
		nil,
	); err != nil {
		t.Fatalf("Evaluate error = %v", err)
	}

	subject := (*got)["subject"].(map[string]any)
	if !reflect.DeepEqual(subject["properties"], map[string]any{"groups": []any{"payments"}}) {
		t.Errorf("subject.properties = %#v, want {groups:[payments]}", subject["properties"])
	}
	resource := (*got)["resource"].(map[string]any)
	if !reflect.DeepEqual(resource["properties"], map[string]any{"labels": map[string]any{"team": "payments"}}) {
		t.Errorf("resource.properties = %#v, want {labels:{team:payments}}", resource["properties"])
	}
}

// TestAuthZenConformance_EvaluationsRequestShape pins the batch request to the AuthZen
// Access Evaluations shape: a top-level `evaluations` array whose items each fully specify
// subject/action/resource.
func TestAuthZenConformance_EvaluationsRequestShape(t *testing.T) {
	srv, got := captureBody(t, `{"evaluations":[{"decision":true},{"decision":false}]}`)
	defer srv.Close()
	d := newDriver(t, srv.URL+"/access/v1/evaluation")

	subject := Subject{Type: "user", ID: "alice@acmecorp.com"}
	if _, err := d.Evaluations(context.Background(), []EvalRequest{
		{Subject: subject, Action: "can_read", Resource: Resource{Type: "todo", ID: "1"}},
		{Subject: subject, Action: "can_delete", Resource: Resource{Type: "todo", ID: "1"}},
	}); err != nil {
		t.Fatalf("Evaluations error = %v", err)
	}

	evals, ok := (*got)["evaluations"].([]any)
	if !ok {
		t.Fatalf("batch body has no top-level evaluations array: %#v", *got)
	}
	if len(evals) != 2 {
		t.Fatalf("evaluations length = %d, want 2", len(evals))
	}
	first := evals[0].(map[string]any)
	want := map[string]any{
		"subject":  map[string]any{"type": "user", "id": "alice@acmecorp.com"},
		"action":   map[string]any{"name": "can_read"},
		"resource": map[string]any{"type": "todo", "id": "1"},
	}
	if !reflect.DeepEqual(first, want) {
		t.Errorf("evaluations[0] =\n%#v\nwant\n%#v", first, want)
	}
	if second := evals[1].(map[string]any)["action"].(map[string]any)["name"]; second != "can_delete" {
		t.Errorf("evaluations[1].action.name = %v, want can_delete", second)
	}
}

// TestAuthZenConformance_ResponseShapes parses the documented AuthZen response variants for
// the single Access Evaluation endpoint.
func TestAuthZenConformance_ResponseShapes(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantAllow  bool
		wantReason string
	}{
		{"boolean allow", `{"decision":true}`, true, ""},
		{"boolean deny", `{"decision":false}`, false, ""},
		{"deny with reason context", `{"decision":false,"context":{"reason":"role not permitted"}}`, false, "role not permitted"},
		{"allow with extra context", `{"decision":true,"context":{"id":"0","reason_admin":{"en":"ok"}}}`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			d := newDriver(t, srv.URL+"/access/v1/evaluation")
			dec, err := d.Evaluate(context.Background(), Subject{Type: "user", ID: "alice@acmecorp.com"}, "can_read", Resource{Type: "todo", ID: "1"}, nil)
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

// TestAuthZenConformance_TodoInteropScenario round-trips the AuthZen interop "Todo"
// application decision scenario through the batch path. The mock PDP plays the Todo policy
// (admin may do everything; a viewer may only read); the driver under test must carry every
// (subject, action, resource) tuple, issue a single batched call, and map each decision back
// in order. This exercises exactly the request/response contract the interop suite uses for
// the Todo app, with CCF as the AuthZen client.
func TestAuthZenConformance_TodoInteropScenario(t *testing.T) {
	policy := map[string]map[string]bool{
		// admin
		"rick@the-citadel.com": {"can_read_todo": true, "can_create_todo": true, "can_update_todo": true, "can_delete_todo": true},
		// viewer — read only
		"summer@the-smiths.com": {"can_read_todo": true, "can_create_todo": false, "can_update_todo": false, "can_delete_todo": false},
	}

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req authzenEvaluationsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode batch request: %v", err)
		}
		resp := authzenEvaluationsResponse{Evaluations: make([]authzenDecisionResponse, len(req.Evaluations))}
		for i, e := range req.Evaluations {
			if e.Resource.Type != "todo" {
				t.Errorf("evaluation[%d].resource.type = %q, want todo", i, e.Resource.Type)
			}
			resp.Evaluations[i] = authzenDecisionResponse{Decision: policy[e.Subject.ID][e.Action.Name]}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	d := newDriver(t, srv.URL+"/access/v1/evaluation")

	subjects := []string{"rick@the-citadel.com", "summer@the-smiths.com"}
	actions := []string{"can_read_todo", "can_create_todo", "can_update_todo", "can_delete_todo"}
	var reqs []EvalRequest
	var want []bool
	for _, s := range subjects {
		for _, a := range actions {
			reqs = append(reqs, EvalRequest{Subject: Subject{Type: "user", ID: s}, Action: a, Resource: Resource{Type: "todo", ID: "1"}})
			want = append(want, policy[s][a])
		}
	}

	decs, err := d.Evaluations(context.Background(), reqs)
	if err != nil {
		t.Fatalf("Evaluations error = %v", err)
	}
	if calls != 1 {
		t.Errorf("HTTP calls = %d, want 1 (the whole interop scenario in one batch)", calls)
	}
	if len(decs) != len(want) {
		t.Fatalf("decisions length = %d, want %d", len(decs), len(want))
	}
	for i := range want {
		if decs[i].Allow != want[i] {
			t.Errorf("decision[%d] (%s / %s) Allow = %v, want %v",
				i, reqs[i].Subject.ID, reqs[i].Action, decs[i].Allow, want[i])
		}
	}
}
