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
// request from the subject's resolved roles. The policy set is read-only after construction
// and each Evaluate builds its own entity store, so it is safe for concurrent use. Roles come
// from a RoleResolver: the DB-backed resolver (the persisted ccf_role_assignments source of
// truth, BCH-1333) reads CCF's database, so unlike Phase 1 the engine can now return an error
// when the role source is unreachable — the PEP's fail mode decides what that means.
type Cedar struct {
	policies *cedar.PolicySet
	roles    RoleResolver
	logger   *zap.SugaredLogger
}

// NewCedar constructs the embedded Cedar PDP from an already-compiled policy set and a role
// resolver. A nil logger is replaced with a no-op; a nil resolver defaults to agents-only (the
// agent service role), which denies every user — callers should pass a loaded resolver. The
// factory does the file IO (manifest compile, operator policy dir, role assignment file) and
// wires the DB-backed resolver; this constructor stays pure for testing. *RoleAssignments
// satisfies RoleResolver, so file-only tests can pass static assignments directly.
func NewCedar(policies *cedar.PolicySet, roles RoleResolver, logger *zap.SugaredLogger) *Cedar {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	if roles == nil {
		roles = &RoleAssignments{Agents: DefaultAgentRole}
	}
	return &Cedar{policies: policies, roles: roles, logger: logger}
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

	// When public agent endpoints are enabled (StrictDisablePublicAgentEndpoints=false),
	// unauthenticated requests to agent ingest routes arrive at the PEP as anonymous
	// subjects (AgentJWTOrPublicMiddleware lets them through without setting agent_claims).
	// Auto-grant them the agent role so Cedar agrees with the PEP's routing decision.
	// An explicit `anonymous:` in the role-assignments file overrides this auto-grant.
	if deps.Config != nil && !deps.Config.StrictDisablePublicAgentEndpoints && assignments.Anonymous == "" {
		assignments.Anonymous = DefaultAgentRole
		logger.Infow("authz cedar: public agent endpoints enabled; anonymous subjects granted agent role",
			"role", DefaultAgentRole)
	}

	if err := assignments.validate(m); err != nil {
		return nil, err
	}
	if len(assignments.Users) == 0 && len(assignments.Groups) == 0 {
		logger.Warnw("authz cedar: no user/group role assignments configured; all users are denied, only agents are authorized (default role)",
			"agentRole", assignments.Agents)
	}

	// The persisted ccf_role_assignments table is the source of truth for user/group roles
	// (BCH-1333): when a DB is available, resolve roles from it (behind a short-TTL cache),
	// falling back to the file's agent/anonymous defaults the table does not hold. authz-roles.yaml
	// becomes the seed BCH-1334 reconciles into the table. Without a DB (some test suites) the
	// static file assignments remain the resolver, so behavior is unchanged there.
	var roles RoleResolver = assignments
	if deps.DB != nil {
		roles = NewDBRoleResolver(deps.DB, assignments, DefaultRoleCacheTTL, logger)
	}

	return NewCedar(policies, roles, logger), nil
}

// Evaluate implements PDP. It resolves the subject's roles, then asks Cedar. A subject with
// no role is denied without consulting Cedar (no bundled permit could match it anyway), which
// also keeps anonymous and unassigned principals from building an entity store needlessly. A
// role-source error is returned to the caller so the PEP fail mode (not a silent allow/deny)
// governs an unreachable DB.
func (c *Cedar) Evaluate(ctx context.Context, s Subject, action string, r Resource, _ map[string]any) (Decision, error) {
	roles, err := c.roles.RolesFor(ctx, s)
	if err != nil {
		return Decision{Allow: false, Reason: "cedar: role resolution failed"}, err
	}
	if len(roles) == 0 {
		return Decision{Allow: false, Reason: "cedar: subject has no assigned role"}, nil
	}
	return c.decide(s, action, r, roles), nil
}

// Evaluations implements PDP by deciding each request in order. Role resolution is memoized
// per subject for the batch (e.g. /me/permissions enumerates ~all actions for one subject),
// so the group parsing and map lookups happen once rather than per action.
func (c *Cedar) Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error) {
	roleMemo := make(map[string][]string)

	out := make([]Decision, len(reqs))
	for i, req := range reqs {
		// Key on everything role resolution depends on — type, id AND the (sorted) groups — so two
		// requests that share a type+id but carry different groups never reuse each other's roles.
		groups := subjectGroups(req.Subject)
		sort.Strings(groups)
		key := req.Subject.Type + "\x00" + req.Subject.ID + "\x00" + strings.Join(groups, ",")
		roles, ok := roleMemo[key]
		if !ok {
			resolved, err := c.roles.RolesFor(ctx, req.Subject)
			if err != nil {
				return nil, err
			}
			roles = resolved
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
	// Don't let the resource entity clobber the principal. When a subject acts on a resource
	// of its own kind keyed by its own id (e.g. an agent on the `agent` resource with
	// resource.ID == subject.ID), principal and resource share a UID; overwriting here would
	// replace the principal's role parents with an empty set and deny a granted request. The
	// shared entity already satisfies `resource is CCF::Agent`/`CCF::User` (same type) with its
	// parents intact, so only add a distinct resource entity.
	if resource != principal {
		entities[resource] = cedar.Entity{UID: resource, Parents: cedar.NewEntityUIDSet()}
	}

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
// gets the Anonymous type, which no bundled policy grants (defense in depth — the role
// resolver already returns no roles for it).
func principalUID(s Subject) cedar.EntityUID {
	var typ string
	switch s.Type {
	case "user":
		typ = cedarUserEntityType
	case "agent":
		typ = cedarAgentEntityType
	case "anonymous":
		typ = cedarAnonymousEntityType
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
