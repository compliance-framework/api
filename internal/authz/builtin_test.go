package authz

import (
	"context"
	"testing"
)

// Non-admin resources are allowed for any request that reaches the PDP, because the authn
// middleware has already gated authentication. These paths never touch the DB, so a nil
// DB is fine and proves it.
func TestBuiltinAllowsNonAdminResources(t *testing.T) {
	b := NewBuiltin(nil, nil, nil)

	cases := []Subject{
		{Type: "user", ID: "alice@example.com"},
		{Type: "agent", ID: "agent-1"},
		{Type: "anonymous"},
	}
	for _, s := range cases {
		dec, err := b.Evaluate(context.Background(), s, ActionCreate, Resource{Type: ResourceEvidence}, nil)
		if err != nil {
			t.Fatalf("Evaluate(evidence) subject=%q error = %v", s.Type, err)
		}
		if !dec.Allow {
			t.Errorf("Evaluate(evidence) subject=%q allow = false, want true (reason %q)", s.Type, dec.Reason)
		}
	}
}

// Admin resources require an authenticated user subject. A missing/non-user subject is
// denied before any DB access, so a nil DB must not panic.
func TestBuiltinAdminDeniesWithoutUserSubject(t *testing.T) {
	b := NewBuiltin(nil, nil, nil)

	for _, s := range []Subject{{Type: "anonymous"}, {Type: "agent", ID: "agent-1"}, {Type: "user", ID: ""}} {
		dec, err := b.Evaluate(context.Background(), s, ActionManage, Resource{Type: ResourceAdmin}, nil)
		if err != nil {
			t.Fatalf("Evaluate(admin) subject=%+v error = %v", s, err)
		}
		if dec.Allow {
			t.Errorf("Evaluate(admin) subject=%+v allow = true, want false", s)
		}
	}
}

// Evaluations returns one decision per request, in order.
func TestBuiltinEvaluationsBatch(t *testing.T) {
	b := NewBuiltin(nil, nil, nil)
	reqs := []EvalRequest{
		{Subject: Subject{Type: "user", ID: "a"}, Action: ActionRead, Resource: Resource{Type: ResourceEvidence}},
		{Subject: Subject{Type: "anonymous"}, Action: ActionManage, Resource: Resource{Type: ResourceAdmin}},
	}
	decs, err := b.Evaluations(context.Background(), reqs)
	if err != nil {
		t.Fatalf("Evaluations error = %v", err)
	}
	if len(decs) != 2 {
		t.Fatalf("len(decisions) = %d, want 2", len(decs))
	}
	if !decs[0].Allow {
		t.Errorf("decision[0] (evidence) allow = false, want true")
	}
	if decs[1].Allow {
		t.Errorf("decision[1] (admin, anonymous) allow = true, want false")
	}
}

func TestBuiltinRegisteredAsDefaultDriver(t *testing.T) {
	found := false
	for _, name := range Drivers() {
		if name == DriverBuiltin {
			found = true
		}
	}
	if !found {
		t.Fatalf("builtin driver not registered; drivers = %v", Drivers())
	}

	pdp, err := Open(Options{}, Deps{})
	if err != nil {
		t.Fatalf("Open(default) error = %v", err)
	}
	if _, ok := pdp.(*Builtin); !ok {
		t.Fatalf("Open(default) returned %T, want *Builtin", pdp)
	}

	if _, err := Open(Options{Driver: "does-not-exist"}, Deps{}); err == nil {
		t.Fatal("Open(unknown driver) expected error, got nil")
	}
}
