package authz

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"go.uber.org/zap"
)

// DriverCedar is the name of the embedded Cedar engine: the OSS built-in PDP (cedar-go,
// in-process). It honors the manifest's bundled global-RBAC roles (C0) and is the shared
// evaluation core the Enterprise external Cedar PDP also builds on (BCH-1319 §11; BCH-1316).
//
// It is registered but NOT yet the default — `builtin` stays the default so this change is
// zero-behavior. Selecting it (authz.driver: cedar) opts a deployment into real RBAC, where
// access requires a role grant (deny-by-default). Making cedar the default is the migration
// tracked in BCH-1330.
const DriverCedar = "cedar"

// Cedar entity types in the CCF namespace. User/Agent mirror the subject types (and the
// cedarEntityName mapping export.go uses), so principals, the bundled policies, the exported
// schema and operator .cedar files all name the same entities.
const (
	cedarActionEntityType    = cedarNamespace + "::Action"
	cedarUserEntityType      = cedarNamespace + "::User"
	cedarAgentEntityType     = cedarNamespace + "::Agent"
	cedarAnonymousEntityType = cedarNamespace + "::Anonymous"
)

func init() {
	Register(DriverCedar, cedarFactory)
}

// Cedar is the embedded Cedar PDP. It evaluates the bundled role policies (compiled from the
// manifest) plus any operator .cedar files against an in-process entity store it builds per
// request from the subject's statically-assigned roles. It is a pure function of (policies,
// entities, request) — it holds no DB handle and reaches no network, so it never returns
// ErrUnavailable and the configured fail mode never changes its behavior. Safe for
// concurrent use: the policy set and assignments are read-only after construction and each
// Evaluate builds its own entity store.
type Cedar struct {
	policies    *cedar.PolicySet
	assignments *RoleAssignments
	logger      *zap.SugaredLogger
}

// NewCedar constructs the embedded Cedar PDP from an already-compiled policy set and the
// static role assignments. A nil logger is replaced with a no-op; nil assignments default to
// agents-only (the agent service role), which denies every user — callers should pass loaded
// assignments. The factory does the file IO (manifest compile, operator policy dir, role
// assignment file); this constructor stays pure for testing.
func NewCedar(policies *cedar.PolicySet, assignments *RoleAssignments, logger *zap.SugaredLogger) *Cedar {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if assignments == nil {
		assignments = &RoleAssignments{Agents: DefaultAgentRole}
	}
	return &Cedar{policies: policies, assignments: assignments, logger: logger}
}

// cedarFactory builds the embedded Cedar PDP: compile the manifest roles into the bundled
// policy set, append any operator .cedar files (GitOps escape hatch), load + validate the
// static role assignments, then construct. Misconfiguration (bad operator policy, malformed
// or role-typo'd assignment file) fails fast at startup rather than per request.
func cedarFactory(_ Options, deps Deps) (PDP, error) {
	logger := deps.Logger
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	m, err := DefaultManifest()
	if err != nil {
		return nil, fmt.Errorf("authz: cedar driver: load manifest: %w", err)
	}
	policies, err := CompileRolePolicies(m)
	if err != nil {
		return nil, err
	}

	var policyDir, assignmentsPath string
	if deps.Config != nil && deps.Config.Authz != nil {
		policyDir = deps.Config.Authz.CedarPolicyDir
		assignmentsPath = deps.Config.Authz.RoleAssignmentsPath
	}

	if policyDir != "" {
		n, err := loadOperatorPolicies(policyDir, policies)
		if err != nil {
			return nil, err
		}
		logger.Infow("authz cedar: loaded operator policies", "dir", policyDir, "policies", n)
	}

	assignments := &RoleAssignments{}
	if assignmentsPath != "" {
		loaded, lerr := LoadRoleAssignments(assignmentsPath)
		switch {
		case lerr == nil:
			assignments = loaded
		case errors.Is(lerr, fs.ErrNotExist):
			logger.Warnw("authz cedar: role-assignment file not found; all users will be denied (agents use the default role)",
				"path", assignmentsPath)
		default:
			return nil, lerr
		}
	}
	assignments.normalize()
	if err := assignments.validate(m); err != nil {
		return nil, err
	}
	if len(assignments.Users) == 0 && len(assignments.Groups) == 0 {
		logger.Warnw("authz cedar: no user/group role assignments configured; all users are denied, only agents are authorized (default role)",
			"agentRole", assignments.Agents)
	}

	return NewCedar(policies, assignments, logger), nil
}

// Evaluate implements PDP. It resolves the subject's roles, then asks Cedar. A subject with
// no role is denied without consulting Cedar (no bundled permit could match it anyway), which
// also keeps anonymous and unassigned principals from building an entity store needlessly.
func (c *Cedar) Evaluate(_ context.Context, s Subject, action string, r Resource, _ map[string]any) (Decision, error) {
	roles := c.assignments.rolesFor(s)
	if len(roles) == 0 {
		return Decision{Allow: false, Reason: "cedar: subject has no assigned role"}, nil
	}
	return c.decide(s, action, r, roles), nil
}

// Evaluations implements PDP by deciding each request in order. Role resolution is memoized
// per subject for the batch (e.g. /me/permissions enumerates ~all actions for one subject),
// so the group parsing and map lookups happen once rather than per action.
func (c *Cedar) Evaluations(_ context.Context, reqs []EvalRequest) ([]Decision, error) {
	type subjectKey struct{ typ, id string }
	roleMemo := make(map[subjectKey][]string)

	out := make([]Decision, len(reqs))
	for i, req := range reqs {
		key := subjectKey{req.Subject.Type, req.Subject.ID}
		roles, ok := roleMemo[key]
		if !ok {
			roles = c.assignments.rolesFor(req.Subject)
			roleMemo[key] = roles
		}
		if len(roles) == 0 {
			out[i] = Decision{Allow: false, Reason: "cedar: subject has no assigned role"}
			continue
		}
		out[i] = c.decide(req.Subject, req.Action, req.Resource, roles)
	}
	return out, nil
}

// decide builds the per-request entity store (the principal, made a member of its role
// entities, plus the resource) and runs Cedar. The decision is deny-by-default: an allow
// requires some bundled (or operator) permit whose role/action/resource scope matches.
func (c *Cedar) decide(s Subject, action string, r Resource, roles []string) Decision {
	principal := principalUID(s)

	entities := cedar.EntityMap{}
	roleUIDs := make([]cedar.EntityUID, len(roles))
	for i, role := range roles {
		uid := cedar.NewEntityUID(cedar.EntityType(cedarRoleEntityType), cedar.String(role))
		roleUIDs[i] = uid
		entities[uid] = cedar.Entity{UID: uid, Parents: cedar.NewEntityUIDSet()}
	}
	entities[principal] = cedar.Entity{UID: principal, Parents: cedar.NewEntityUIDSet(roleUIDs...)}

	resource := resourceUID(r)
	entities[resource] = cedar.Entity{UID: resource, Parents: cedar.NewEntityUIDSet()}

	req := cedar.Request{
		Principal: principal,
		Action:    cedar.NewEntityUID(cedar.EntityType(cedarActionEntityType), cedar.String(action)),
		Resource:  resource,
	}

	decision, diag := cedar.Authorize(c.policies, entities, req)
	if len(diag.Errors) > 0 {
		// Our generated policies never error; an operator .cedar file might. Log and treat
		// the erroring policy as non-matching (Cedar already excluded it from the decision).
		c.logger.Warnw("authz cedar: policy evaluation errors", "errors", diag.Errors)
	}
	if decision == cedar.Allow {
		return Decision{Allow: true, Reason: "cedar: allowed via role(s) " + strings.Join(roles, ",")}
	}
	return Decision{Allow: false, Reason: "cedar: no role grant for action " + action + " on " + r.Type}
}

// principalUID maps a subject to its Cedar principal entity. The type mirrors the subject
// type (user/agent) so it matches the User/Agent entities in the schema; an unexpected type
// gets the Anonymous type, which no bundled policy grants (defense in depth — rolesFor
// already returns no roles for it).
func principalUID(s Subject) cedar.EntityUID {
	var typ string
	switch s.Type {
	case "user":
		typ = cedarUserEntityType
	case "agent":
		typ = cedarAgentEntityType
	default:
		typ = cedarAnonymousEntityType
	}
	return cedar.NewEntityUID(cedar.EntityType(typ), cedar.String(s.ID))
}

// resourceUID maps a PEP resource (the manifest resource key + instance id) to its Cedar
// entity, using the same PascalCase namespacing as the exported schema (poam_item ->
// CCF::PoamItem). The instance id may be empty (create/list routes); the bundled policies
// decide on the entity TYPE, so an empty id still authorizes correctly.
func resourceUID(r Resource) cedar.EntityUID {
	typ := cedarNamespace + "::" + cedarEntityName(r.Type)
	return cedar.NewEntityUID(cedar.EntityType(typ), cedar.String(r.ID))
}

// loadOperatorPolicies parses every *.cedar file in dir (sorted for determinism) and adds its
// policies to set under collision-free ids ("op:<file>:<id>"), so operator policies augment
// the bundled roles. Cedar is deny-by-default with forbid overriding permit, so an operator
// file can both grant beyond the roles and carve forbid exceptions out of them. A parse error
// in any file is fatal at startup. Returns the number of operator policies added.
func loadOperatorPolicies(dir string, set *cedar.PolicySet) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("authz: read cedar policy dir %s: %w", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cedar") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	count := 0
	for _, name := range names {
		full := filepath.Join(dir, name)
		data, err := os.ReadFile(full)
		if err != nil {
			return count, fmt.Errorf("authz: read cedar policy %s: %w", full, err)
		}
		ps, err := cedar.NewPolicySetFromBytes(name, data)
		if err != nil {
			return count, fmt.Errorf("authz: parse cedar policy %s: %w", full, err)
		}
		for id, p := range ps.All() {
			set.Add(cedar.PolicyID(fmt.Sprintf("op:%s:%s", name, id)), p)
			count++
		}
	}
	return count, nil
}
