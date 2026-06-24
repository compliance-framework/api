package authz

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/compliance-framework/api/internal/config"
	"go.uber.org/zap"
)

func mustCedar(t *testing.T, ra *RoleAssignments) *Cedar {
	t.Helper()
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	ps, err := CompileRolePolicies(m)
	if err != nil {
		t.Fatal(err)
	}
	ra.normalize()
	if err := ra.validate(m); err != nil {
		t.Fatal(err)
	}
	return NewCedar(ps, ra, zap.NewNop().Sugar())
}

func allows(t *testing.T, c *Cedar, s Subject, action, resource string) bool {
	t.Helper()
	d, err := c.Evaluate(context.Background(), s, action, Resource{Type: resource, ID: "instance-1"}, nil)
	if err != nil {
		t.Fatalf("Evaluate(%s, %s) error = %v", resource, action, err)
	}
	return d.Allow
}

// The core RBAC matrix: each of the four bundled roles (plus the agent service role) honors
// exactly the manifest's role→resource→action grants, deny-by-default everywhere else.
func TestCedarRBACMatrix(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{
		Users: map[string]string{
			"admin@x":       "admin",
			"viewer@x":      "viewer",
			"auditor@x":     "auditor",
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
		// admin: everything
		{user("admin@x"), "manage", "admin", true},
		{user("admin@x"), "delete", "evidence", true},
		{user("admin@x"), "create", "catalog", true},
		{user("admin@x"), "promote", "risk", true},

		// viewer: read anything; no writes
		{user("viewer@x"), "read", "evidence", true},
		{user("viewer@x"), "read", "catalog", true},
		{user("viewer@x"), "create", "evidence", false},
		{user("viewer@x"), "promote", "risk", false},
		{user("viewer@x"), "manage", "admin", false},

		// auditor: read anything; evidence create; risk create/update/promote; poam create/update
		{user("auditor@x"), "read", "catalog", true},
		{user("auditor@x"), "create", "evidence", true},
		{user("auditor@x"), "delete", "evidence", false},
		{user("auditor@x"), "promote", "risk", true},
		{user("auditor@x"), "delete", "risk", false},
		{user("auditor@x"), "update", "poam_item", true},
		{user("auditor@x"), "delete", "poam_item", false},
		{user("auditor@x"), "create", "catalog", false},
		{user("auditor@x"), "manage", "admin", false},

		// contributor: full CRUD on content; read anything; no admin
		{user("contributor@x"), "delete", "evidence", true},
		{user("contributor@x"), "create", "catalog", true},
		{user("contributor@x"), "delete", "poam_item", true},
		{user("contributor@x"), "promote", "risk", true},
		{user("contributor@x"), "create", "workflow-definition", true},
		{user("contributor@x"), "read", "agent", true}, // via "*": [read]
		{user("contributor@x"), "create", "agent", false},
		{user("contributor@x"), "manage", "admin", false},

		// agent service role
		{agent, "create", "evidence", true},
		{agent, "ingest", "heartbeat", true},
		{agent, "register", "agent", true},
		{agent, "ingest", "agent", true},
		{agent, "update", "risk-template", true},    // plugin v2 batch upsert
		{agent, "update", "subject-template", true},  // plugin v2 batch upsert
		{agent, "delete", "risk-template", false},    // batch route only enforces update
		{agent, "read", "catalog", false},
		{agent, "delete", "evidence", false},
		{agent, "manage", "admin", false},

		// no role / anonymous: deny-by-default
		{user("nobody@x"), "read", "evidence", false},
		{Subject{Type: "anonymous"}, "read", "evidence", false},
	}
	for _, tc := range cases {
		if got := allows(t, c, tc.subj, tc.action, tc.resource); got != tc.want {
			t.Errorf("%s %s on %s: allow = %v, want %v", tc.subj.ID, tc.action, tc.resource, got, tc.want)
		}
	}
}

// Create/list routes carry no instance id; the bundled policies decide on the resource TYPE,
// so an empty Resource.ID must authorize exactly as a non-empty one does.
func TestCedarEmptyResourceID(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{Users: map[string]string{"c@x": "contributor"}})
	subj := Subject{Type: "user", ID: "c@x"}
	d, err := c.Evaluate(context.Background(), subj, "create", Resource{Type: "evidence", ID: ""}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow {
		t.Error("contributor create evidence with empty id: want allow")
	}
	d, _ = c.Evaluate(context.Background(), subj, "manage", Resource{Type: "admin", ID: ""}, nil)
	if d.Allow {
		t.Error("contributor manage admin with empty id: want deny")
	}
}

// Regression: a subject acting on a resource of its own kind keyed by its own id (agent on
// the `agent` resource, resource.ID == subject.ID) must not have its role parents clobbered
// by the resource entity. The agent role grants register/ingest on agent, so all three id
// shapes (own id, different id, empty) must allow.
func TestCedarSelfResourceNoCollision(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{}) // agents default to the agent role
	agent := Subject{Type: "agent", ID: "agent-1"}
	for _, id := range []string{"agent-1", "other", ""} {
		d, err := c.Evaluate(context.Background(), agent, "ingest", Resource{Type: "agent", ID: id}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allow {
			t.Errorf("agent ingest on agent resource id=%q: allow=false, want true", id)
		}
	}
}

// Regression: the batch memo must key on groups too, so two requests sharing a (type,id) but
// carrying different groups can't reuse each other's roles.
func TestCedarEvaluationsHeterogeneousGroups(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{Groups: map[string]string{"admins": "admin"}})
	reqs := []EvalRequest{
		{Subject: Subject{Type: "user", ID: "u@x", Props: map[string]any{"groups": []string{"admins"}}}, Action: "manage", Resource: Resource{Type: "admin"}},
		{Subject: Subject{Type: "user", ID: "u@x"}, Action: "manage", Resource: Resource{Type: "admin"}},
	}
	out, err := c.Evaluations(context.Background(), reqs)
	if err != nil {
		t.Fatal(err)
	}
	if !out[0].Allow {
		t.Error("in-group subject should be allowed (admin via group)")
	}
	if out[1].Allow {
		t.Error("same id without groups must not reuse the in-group roles")
	}
}

// A subject with no assigned role is denied without consulting Cedar, and the reason marks it.
func TestCedarDenyNoRole(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{})
	d, err := c.Evaluate(context.Background(), Subject{Type: "user", ID: "x@y"}, "read", Resource{Type: "evidence"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allow {
		t.Fatal("unassigned user allowed, want deny")
	}
	if d.Reason == "" {
		t.Error("deny reason is empty")
	}
}

// Group-based assignment is live the moment the subject carries a groups attribute (the
// BCH-1328 surface); until then no subject has groups so it is inert. Here we supply groups
// directly to prove the mapping works.
func TestCedarGroupAssignment(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{Groups: map[string]string{"sec-team": "admin"}})

	inGroup := Subject{Type: "user", ID: "alice@x", Props: map[string]any{"groups": []string{"sec-team"}}}
	if !allows(t, c, inGroup, "manage", "admin") {
		t.Error("group sec-team -> admin: manage admin should be allowed")
	}
	noGroup := Subject{Type: "user", ID: "alice@x"}
	if allows(t, c, noGroup, "manage", "admin") {
		t.Error("same user without groups should be denied (group surface inert)")
	}
}

// A subject accumulates the union of its direct grant and every matching group grant.
func TestCedarMultiRoleUnion(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{
		Users:  map[string]string{"m@x": "viewer"},
		Groups: map[string]string{"writers": "contributor"},
	})
	s := Subject{Type: "user", ID: "m@x", Props: map[string]any{"groups": []any{"writers"}}}
	if !allows(t, c, s, "read", "catalog") {
		t.Error("viewer grant: read catalog should be allowed")
	}
	if !allows(t, c, s, "delete", "evidence") {
		t.Error("contributor grant via group: delete evidence should be allowed")
	}
}

// Agents are authorized by the default agent role with zero configuration.
func TestCedarAgentDefaultRole(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{}) // normalize() defaults agents -> "agent"
	agent := Subject{Type: "agent", ID: "a-1"}
	if !allows(t, c, agent, "create", "evidence") {
		t.Error("agent default role: create evidence should be allowed")
	}
	if allows(t, c, agent, "read", "catalog") {
		t.Error("agent default role: read catalog should be denied")
	}
}

func cedarWithOperatorDir(t *testing.T, ra *RoleAssignments, dir string) *Cedar {
	t.Helper()
	m, err := DefaultManifest()
	if err != nil {
		t.Fatal(err)
	}
	ps, err := CompileRolePolicies(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadOperatorPolicies(dir, ps); err != nil {
		t.Fatalf("loadOperatorPolicies() error = %v", err)
	}
	ra.normalize()
	if err := ra.validate(m); err != nil {
		t.Fatal(err)
	}
	return NewCedar(ps, ra, zap.NewNop().Sugar())
}

// The GitOps escape hatch: an operator .cedar file augments the bundled roles (path 1, §11.2).
func TestCedarOperatorPolicyAugments(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "extra.cedar"), []byte(`
permit (
  principal in CCF::Role::"viewer",
  action in [CCF::Action::"create"],
  resource is CCF::Evidence
);
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cedarWithOperatorDir(t, &RoleAssignments{Users: map[string]string{"v@x": "viewer"}}, dir)
	if !allows(t, c, Subject{Type: "user", ID: "v@x"}, "create", "evidence") {
		t.Error("operator policy should grant viewer create evidence")
	}
}

// An operator forbid overrides the bundled permits (Cedar forbid > permit), so operators can
// carve exceptions out of even the admin role without editing CCF.
func TestCedarOperatorForbidOverrides(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lockdown.cedar"), []byte(`
forbid (
  principal,
  action,
  resource is CCF::Admin
);
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cedarWithOperatorDir(t, &RoleAssignments{Users: map[string]string{"admin@x": "admin"}}, dir)
	if allows(t, c, Subject{Type: "user", ID: "admin@x"}, "manage", "admin") {
		t.Error("operator forbid should override the admin permit on admin")
	}
	// The forbid is scoped to admin only — other admin grants still hold.
	if !allows(t, c, Subject{Type: "user", ID: "admin@x"}, "delete", "evidence") {
		t.Error("forbid on admin must not affect evidence")
	}
}

// The batch path must agree with the single path (it is used by /me/permissions).
func TestCedarEvaluationsMatchesEvaluate(t *testing.T) {
	c := mustCedar(t, &RoleAssignments{Users: map[string]string{"a@x": "auditor"}})
	subj := Subject{Type: "user", ID: "a@x"}
	probes := []struct{ action, resource string }{
		{"read", "catalog"},
		{"create", "evidence"},
		{"delete", "evidence"},
		{"promote", "risk"},
		{"manage", "admin"},
	}
	reqs := make([]EvalRequest, len(probes))
	for i, p := range probes {
		reqs[i] = EvalRequest{Subject: subj, Action: p.action, Resource: Resource{Type: p.resource, ID: "x"}}
	}
	batch, err := c.Evaluations(context.Background(), reqs)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != len(reqs) {
		t.Fatalf("Evaluations returned %d, want %d", len(batch), len(reqs))
	}
	for i, p := range probes {
		single := allows(t, c, subj, p.action, p.resource)
		if batch[i].Allow != single {
			t.Errorf("%s %s: batch=%v single=%v", p.action, p.resource, batch[i].Allow, single)
		}
	}
}

// Anonymous subjects with a configured role are granted accordingly; without the field they
// are denied (the safer default). This is the Option B anonymous-role-assignment feature.
func TestCedarAnonymousRole(t *testing.T) {
	// With anonymous: viewer, unauthenticated requests can read but not write.
	c := mustCedar(t, &RoleAssignments{Anonymous: "viewer"})
	anon := Subject{Type: "anonymous"}
	if !allows(t, c, anon, "read", "evidence") {
		t.Error("anonymous viewer: read evidence should be allowed")
	}
	if allows(t, c, anon, "create", "evidence") {
		t.Error("anonymous viewer: create evidence should be denied")
	}
	if allows(t, c, anon, "manage", "admin") {
		t.Error("anonymous viewer: manage admin should be denied")
	}

	// Without the anonymous field, unauthenticated subjects are denied everything.
	cNone := mustCedar(t, &RoleAssignments{})
	if allows(t, cNone, anon, "read", "evidence") {
		t.Error("anonymous without grant: read evidence should be denied")
	}
}

// The driver self-registers under "cedar".
func TestCedarRegistered(t *testing.T) {
	found := false
	for _, d := range Drivers() {
		if d == DriverCedar {
			found = true
		}
	}
	if !found {
		t.Errorf("Drivers() = %v, missing %q", Drivers(), DriverCedar)
	}
}

// When StrictDisablePublicAgentEndpoints is false (default), the factory auto-grants the
// agent role to anonymous subjects so Cedar agrees with AgentJWTOrPublicMiddleware's routing.
// When true, anonymous is denied. An explicit `anonymous:` in the YAML always overrides.
func TestCedarFactoryPublicAgentEndpoints(t *testing.T) {
	anon := Subject{Type: "anonymous"}
	agentActions := []struct{ action, resource string }{
		{"create", "evidence"},
		{"ingest", "heartbeat"},
		{"register", "agent"},
		{"ingest", "agent"},
		{"update", "risk-template"},
		{"update", "subject-template"},
	}

	// Flag false (public open): anonymous gets the agent role automatically.
	cfgOpen := &config.Config{StrictDisablePublicAgentEndpoints: false}
	pdpOpen, err := cedarFactory(Options{}, Deps{Config: cfgOpen, Logger: zap.NewNop().Sugar()})
	if err != nil {
		t.Fatalf("cedarFactory(public open) error = %v", err)
	}
	for _, a := range agentActions {
		d, err := pdpOpen.Evaluate(context.Background(), anon, a.action, Resource{Type: a.resource}, nil)
		if err != nil || !d.Allow {
			t.Errorf("public open: anonymous %s %s: allow=%v err=%v, want allow", a.action, a.resource, d.Allow, err)
		}
	}
	// Anonymous must not get non-agent permissions even when public endpoints are open.
	d, _ := pdpOpen.Evaluate(context.Background(), anon, "manage", Resource{Type: "admin"}, nil)
	if d.Allow {
		t.Error("public open: anonymous manage admin should be denied")
	}

	// Flag true (strict): anonymous is denied even for agent actions.
	cfgStrict := &config.Config{StrictDisablePublicAgentEndpoints: true}
	pdpStrict, err := cedarFactory(Options{}, Deps{Config: cfgStrict, Logger: zap.NewNop().Sugar()})
	if err != nil {
		t.Fatalf("cedarFactory(strict) error = %v", err)
	}
	d, _ = pdpStrict.Evaluate(context.Background(), anon, "create", Resource{Type: "evidence"}, nil)
	if d.Allow {
		t.Error("strict mode: anonymous create evidence should be denied")
	}

	// Explicit YAML `anonymous: viewer` overrides the auto-grant.
	dir := t.TempDir()
	rolesFile := t.TempDir() + "/roles.yaml"
	if err := os.WriteFile(rolesFile, []byte("anonymous: viewer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = dir
	cfgOverride := &config.Config{
		StrictDisablePublicAgentEndpoints: false,
		Authz: &config.AuthzConfig{RoleAssignmentsPath: rolesFile},
	}
	pdpOverride, err := cedarFactory(Options{}, Deps{Config: cfgOverride, Logger: zap.NewNop().Sugar()})
	if err != nil {
		t.Fatalf("cedarFactory(yaml override) error = %v", err)
	}
	// viewer can read but cannot create evidence (agent action)
	d, _ = pdpOverride.Evaluate(context.Background(), anon, "read", Resource{Type: "evidence"}, nil)
	if !d.Allow {
		t.Error("yaml override viewer: anonymous read evidence should be allowed")
	}
	d, _ = pdpOverride.Evaluate(context.Background(), anon, "create", Resource{Type: "evidence"}, nil)
	if d.Allow {
		t.Error("yaml override viewer: anonymous create evidence should be denied (viewer, not agent)")
	}
}

// The factory wires the config paths end-to-end: it loads the assignment file, validates
// roles, and produces a working PDP. A missing optional file is tolerated; a bad one fails.
func TestCedarFactory(t *testing.T) {
	dir := t.TempDir()
	rolesFile := filepath.Join(dir, "authz-roles.yaml")
	if err := os.WriteFile(rolesFile, []byte("users:\n  admin@x: admin\n  viewer@x: viewer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Authz: &config.AuthzConfig{Driver: "cedar", RoleAssignmentsPath: rolesFile}}
	pdp, err := cedarFactory(Options{Driver: "cedar"}, Deps{Config: cfg, Logger: zap.NewNop().Sugar()})
	if err != nil {
		t.Fatalf("cedarFactory() error = %v", err)
	}
	d, err := pdp.Evaluate(context.Background(), Subject{Type: "user", ID: "admin@x"}, "manage", Resource{Type: "admin"}, nil)
	if err != nil || !d.Allow {
		t.Errorf("admin manage admin: allow=%v err=%v, want allow", d.Allow, err)
	}
	d, _ = pdp.Evaluate(context.Background(), Subject{Type: "user", ID: "viewer@x"}, "create", Resource{Type: "evidence"}, nil)
	if d.Allow {
		t.Error("viewer create evidence: want deny")
	}

	// Missing optional file: factory still builds (agents authorized, users denied).
	cfgMissing := &config.Config{Authz: &config.AuthzConfig{Driver: "cedar", RoleAssignmentsPath: filepath.Join(dir, "absent.yaml")}}
	if _, err := cedarFactory(Options{}, Deps{Config: cfgMissing, Logger: zap.NewNop().Sugar()}); err != nil {
		t.Errorf("cedarFactory(missing file) error = %v, want nil", err)
	}

	// A role typo fails fast at startup.
	badFile := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badFile, []byte("users:\n  a@x: audtor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgBad := &config.Config{Authz: &config.AuthzConfig{Driver: "cedar", RoleAssignmentsPath: badFile}}
	if _, err := cedarFactory(Options{}, Deps{Config: cfgBad, Logger: zap.NewNop().Sugar()}); err == nil {
		t.Error("cedarFactory(unknown role) error = nil, want error")
	}
}

// The factory honors CedarPolicyDir end-to-end: operator .cedar files are appended to the
// bundled roles and take effect through the constructed PDP.
func TestCedarFactoryLoadsPolicyDir(t *testing.T) {
	dir := t.TempDir()
	rolesFile := filepath.Join(dir, "authz-roles.yaml")
	if err := os.WriteFile(rolesFile, []byte("users:\n  v@x: viewer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policyDir := filepath.Join(dir, "policies")
	if err := os.Mkdir(policyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "extra.cedar"), []byte(
		"permit (\n  principal in CCF::Role::\"viewer\",\n  action in [CCF::Action::\"create\"],\n  resource is CCF::Evidence\n);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Authz: &config.AuthzConfig{Driver: "cedar", RoleAssignmentsPath: rolesFile, CedarPolicyDir: policyDir}}
	pdp, err := cedarFactory(Options{}, Deps{Config: cfg, Logger: zap.NewNop().Sugar()})
	if err != nil {
		t.Fatalf("cedarFactory() error = %v", err)
	}
	d, err := pdp.Evaluate(context.Background(), Subject{Type: "user", ID: "v@x"}, "create", Resource{Type: "evidence"}, nil)
	if err != nil || !d.Allow {
		t.Errorf("operator policy via factory: allow=%v err=%v, want allow", d.Allow, err)
	}
}

// Open selects the cedar driver by name and applies the optional decision cache wrapper.
func TestOpenCedarDriver(t *testing.T) {
	dir := t.TempDir()
	rolesFile := filepath.Join(dir, "authz-roles.yaml")
	if err := os.WriteFile(rolesFile, []byte("users:\n  admin@x: admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Authz: &config.AuthzConfig{Driver: DriverCedar, RoleAssignmentsPath: rolesFile}}
	pdp, err := Open(Options{Driver: DriverCedar}, Deps{Config: cfg, Logger: zap.NewNop().Sugar()})
	if err != nil {
		t.Fatalf("Open(cedar) error = %v", err)
	}
	d, err := pdp.Evaluate(context.Background(), Subject{Type: "user", ID: "admin@x"}, "manage", Resource{Type: "admin"}, nil)
	if err != nil || !d.Allow {
		t.Errorf("Open(cedar) admin manage: allow=%v err=%v", d.Allow, err)
	}
}
