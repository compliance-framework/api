package authz

import (
	"context"
	"slices"
	"testing"
)

// Agent remote configuration vocabulary (A2.4): the agent resource declares configure and
// sync.
func TestManifestAgentConfigVocabulary(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	res, ok := m.Resources[ResourceAgent]
	if !ok {
		t.Fatal("agent resource missing from manifest")
	}
	for _, action := range []string{ActionRead, ActionRegister, ActionIngest, ActionConfigure, ActionSync} {
		if !slices.Contains(res.Actions, action) {
			t.Errorf("agent resource missing action %q (have %v)", action, res.Actions)
		}
	}
	if got := m.Roles["agent"][ResourceAgent]; !slices.Contains(got, ActionSync) {
		t.Errorf("agent role agent grants = %v, want sync", got)
	}
}

// The Cedar matrix for the new actions (A2 tests).
func TestCedarAgentConfigMatrix(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{
		Users: map[string]string{
			"admin@x":       "admin",
			"viewer@x":      "viewer",
			"contributor@x": "contributor",
		},
	})
	user := func(id string) Subject { return Subject{Type: "user", ID: id} }
	agent := Subject{Type: "agent", ID: "agent-1"}

	cases := []struct {
		subj     Subject
		action   string
		resource string
		want     bool
	}{
		{agent, ActionSync, ResourceAgent, true},
		{agent, ActionConfigure, ResourceAgent, false},
		{agent, ActionRead, ResourceAgent, false},

		{user("viewer@x"), ActionRead, ResourceAgent, true},
		{user("viewer@x"), ActionConfigure, ResourceAgent, false},
		{user("viewer@x"), ActionSync, ResourceAgent, false},
		{user("viewer@x"), ActionRead, ResourceArtifact, true}, // "*": [read] covers #464 artifacts
		{user("viewer@x"), ActionIngest, ResourceArtifact, false},
		{user("contributor@x"), ActionRead, ResourceAgent, true},
		{user("contributor@x"), ActionConfigure, ResourceAgent, false},

		{user("admin@x"), ActionConfigure, ResourceAgent, true},

		{Subject{Type: "anonymous"}, ActionRead, ResourceAgent, false},
	}
	for _, tc := range cases {
		if got := allows(t, c, tc.subj, tc.action, tc.resource); got != tc.want {
			t.Errorf("%s %s on %s: allow = %v, want %v", tc.subj.ID, tc.action, tc.resource, got, tc.want)
		}
	}
}

// Builtin (R39): agent service accounts are allowed on the agent resource, anonymous is
// denied, and users go through the admin check (a user subject without an id is denied
// before any DB access, so a nil DB proves the admin path is taken).
func TestBuiltinAgentResource(t *testing.T) {
	b := NewBuiltin(nil, nil, nil)
	ctx := context.Background()

	for _, action := range []string{ActionRegister, ActionIngest, ActionSync} {
		dec, err := b.Evaluate(ctx, Subject{Type: "agent", ID: "agent-1"}, action, Resource{Type: ResourceAgent}, nil)
		if err != nil || !dec.Allow {
			t.Errorf("agent %s: allow=%v err=%v, want allow", action, dec.Allow, err)
		}
	}
	for _, action := range []string{ActionRead, ActionConfigure, ActionSync} {
		dec, err := b.Evaluate(ctx, Subject{Type: "anonymous"}, action, Resource{Type: ResourceAgent}, nil)
		if err != nil || dec.Allow {
			t.Errorf("anonymous %s: allow=%v err=%v, want deny", action, dec.Allow, err)
		}
	}
	dec, err := b.Evaluate(ctx, Subject{Type: "user", ID: ""}, ActionRead, Resource{Type: ResourceAgent}, nil)
	if err != nil || dec.Allow {
		t.Errorf("user without id on agent:read: allow=%v err=%v, want deny via the admin check", dec.Allow, err)
	}

	// Batch: the user admin decision is memoized across agent and admin requests.
	decs, err := b.Evaluations(ctx, []EvalRequest{
		{Subject: Subject{Type: "user", ID: ""}, Action: ActionConfigure, Resource: Resource{Type: ResourceAgent}},
		{Subject: Subject{Type: "user", ID: ""}, Action: ActionManage, Resource: Resource{Type: ResourceAdmin}},
		{Subject: Subject{Type: "agent", ID: "a"}, Action: ActionSync, Resource: Resource{Type: ResourceAgent}},
		{Subject: Subject{Type: "user", ID: "x@y"}, Action: ActionRead, Resource: Resource{Type: ResourceEvidence}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{false, false, true, true}
	for i, d := range decs {
		if d.Allow != want[i] {
			t.Errorf("batch[%d] allow = %v, want %v", i, d.Allow, want[i])
		}
	}
}
