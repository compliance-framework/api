package authz

import (
	"context"
	"slices"
	"testing"
)

// Agent remote configuration vocabulary (A2.4): the agent resource declares configure,
// configure-policy and sync, and the bundled policy-author role exists.
func TestManifestAgentConfigVocabulary(t *testing.T) {
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	res, ok := m.Resources[ResourceAgent]
	if !ok {
		t.Fatal("agent resource missing from manifest")
	}
	for _, action := range []string{ActionRead, ActionRegister, ActionIngest, ActionConfigure, ActionConfigurePolicy, ActionSync} {
		if !slices.Contains(res.Actions, action) {
			t.Errorf("agent resource missing action %q (have %v)", action, res.Actions)
		}
	}
	author, ok := m.Roles["policy-author"]
	if !ok {
		t.Fatal("policy-author role missing")
	}
	if got := author[ResourceAgent]; !slices.Contains(got, ActionConfigurePolicy) || !slices.Contains(got, ActionRead) || slices.Contains(got, ActionConfigure) {
		t.Errorf("policy-author agent grants = %v, want read + configure-policy only", got)
	}
	if got := author["*"]; !slices.Equal(got, []string{ActionRead}) {
		t.Errorf(`policy-author "*" grants = %v, want [read] (R53)`, got)
	}
	if got := m.Roles["agent"][ResourceAgent]; !slices.Contains(got, ActionSync) {
		t.Errorf("agent role agent grants = %v, want sync", got)
	}
}

// The Cedar matrix for the new actions and the policy-author role (A2 tests).
func TestCedarAgentConfigMatrix(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{
		Users: map[string]string{
			"admin@x":       "admin",
			"viewer@x":      "viewer",
			"contributor@x": "contributor",
			"author@x":      "policy-author",
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
		{agent, ActionConfigurePolicy, ResourceAgent, false},
		{agent, ActionRead, ResourceAgent, false},

		{user("author@x"), ActionConfigurePolicy, ResourceAgent, true},
		{user("author@x"), ActionRead, ResourceAgent, true},
		{user("author@x"), ActionConfigure, ResourceAgent, false},
		{user("author@x"), ActionSync, ResourceAgent, false},
		{user("author@x"), ActionRead, ResourceCatalog, true}, // "*": [read] (R53)
		{user("author@x"), ActionCreate, ResourceCatalog, false},
		{user("author@x"), ActionManage, ResourceAdmin, false},
		{user("author@x"), ActionExecute, ResourcePlayback, true},

		{user("viewer@x"), ActionRead, ResourceAgent, true},
		{user("viewer@x"), ActionConfigure, ResourceAgent, false},
		{user("viewer@x"), ActionConfigurePolicy, ResourceAgent, false},
		{user("contributor@x"), ActionRead, ResourceAgent, true},
		{user("contributor@x"), ActionConfigure, ResourceAgent, false},

		{user("admin@x"), ActionConfigure, ResourceAgent, true},
		{user("admin@x"), ActionConfigurePolicy, ResourceAgent, true},

		{Subject{Type: "anonymous"}, ActionRead, ResourceAgent, false},
	}
	for _, tc := range cases {
		if got := allows(t, c, tc.subj, tc.action, tc.resource); got != tc.want {
			t.Errorf("%s %s on %s: allow = %v, want %v", tc.subj.ID, tc.action, tc.resource, got, tc.want)
		}
	}
}

// R53 (file-seed variant): a user's own viewer grant and a group's policy-author grant combine.
func TestCedarMultiRoleUnionPolicyAuthor(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{
		Users:  map[string]string{"u@x": "viewer"},
		Groups: map[string]string{"ccf-policy-authors": "policy-author"},
	})
	withGroup := Subject{Type: "user", ID: "u@x", Props: map[string]any{"groups": []any{"ccf-policy-authors"}}}
	if !allows(t, c, withGroup, ActionConfigurePolicy, ResourceAgent) {
		t.Error("configure-policy via the group grant should be allowed")
	}
	if !allows(t, c, withGroup, ActionRead, ResourceCatalog) {
		t.Error("read catalog via the direct viewer grant should be allowed")
	}
	if allows(t, c, withGroup, ActionConfigure, ResourceAgent) {
		t.Error("configure should be denied: neither grant includes it")
	}
	withoutGroup := Subject{Type: "user", ID: "u@x"}
	if allows(t, c, withoutGroup, ActionConfigurePolicy, ResourceAgent) {
		t.Error("configure-policy without the group membership should be denied")
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
