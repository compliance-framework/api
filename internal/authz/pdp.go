// Package authz is CCF's central authorization layer. It defines the engine-neutral
// PDP (Policy Decision Point) contract that the PEP middleware calls, a driver registry
// that mirrors database/sql, a loader for the authorization manifest, and a builtin
// driver that reproduces CCF's pre-authz access rules with zero behavior change.
//
// See the "CCF Pluggable Authorization — Design Plan" (BCH-1313, Phase 1). CCF declares
// the vocabulary, the PEP supplies facts, and the configured PDP decides; CCF never
// stores or evaluates policies beyond what the builtin driver needs.
package authz

import "context"

// Subject is the actor a decision is made about — an authenticated user or agent (or an
// anonymous subject on public-allowed routes). Props carries provisional, minimal
// attributes in Phase 1; the authoritative per-resource attribute surface is designed
// separately in BCH-1319 and must not be grown ad hoc here.
type Subject struct {
	Type  string
	ID    string
	Props map[string]any
}

// Resource is the thing being acted upon.
type Resource struct {
	Type  string
	ID    string
	Props map[string]any
}

// Decision is the PDP's verdict. Reason is for logging only and is never echoed to
// clients (see the PEP).
type Decision struct {
	Allow  bool
	Reason string
}

// EvalRequest is one entry in a batch evaluation (AuthZen "evaluations"), used for list
// filtering and UI permission hints.
type EvalRequest struct {
	Subject  Subject
	Action   string
	Resource Resource
	Context  map[string]any
}

// PDP is the pluggable decision engine. Implementations must be safe for concurrent use.
type PDP interface {
	// Evaluate returns the decision for a single (subject, action, resource) tuple.
	Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error)
	// Evaluations returns decisions for a batch of requests, in the same order.
	Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error)
}

// Healther is an optional capability a PDP may implement to report whether its decision
// engine is reachable. The readiness check surfaces it; in-process drivers that cannot
// fail (builtin) simply don't implement it and are treated as healthy.
type Healther interface {
	Health(ctx context.Context) error
}

// Resource and action identifiers, all declared in manifest.yaml. These are the strings the
// PEP hands the PDP; they must match the manifest (and the cedar entity mapping in cedar.go)
// EXACTLY — the hyphen/underscore split is load-bearing (poam_item/poam_oscal use
// underscores, OSCAL document resources use hyphens). ActionManage is the umbrella admin
// action: every admin route enforces it uniformly, while the manifest also declares the
// granular admin.* actions for later per-route enforcement.
const (
	// Platform / admin (archetype F).
	ResourceAdmin           = "admin"
	ResourceUser            = "user"
	ResourceAgent           = "agent"
	ResourceNotification    = "notification"
	ResourceRiskTemplate    = "risk-template"
	ResourceSubjectTemplate = "subject-template"
	ResourceDigest          = "digest"
	ResourceAIDiagnostics   = "ai-diagnostics"
	ResourceImport          = "import"

	// Telemetry / ingest (archetype C).
	ResourceEvidence  = "evidence"
	ResourceHeartbeat = "heartbeat"

	// OSCAL authoring documents (archetype A).
	ResourceCatalog             = "catalog"
	ResourceProfile             = "profile"
	ResourceComponentDefinition = "component-definition"
	ResourceSSP                 = "ssp"
	ResourceAssessmentPlan      = "assessment-plan"
	ResourceAssessmentResults   = "assessment-results"
	ResourcePoamOSCAL           = "poam_oscal"
	ResourceInventory           = "inventory"
	ResourceParty               = "party"
	ResourceRole                = "role"
	ResourceActivity            = "activity"

	// SSP-scoped register items (archetype B).
	ResourceRisk     = "risk"
	ResourcePoamItem = "poam_item"

	// Dashboard / config (archetype E).
	ResourceFilter              = "filter"
	ResourceDashboardSuggestion = "dashboard-suggestion"

	// Workflow engine (archetype D).
	ResourceWorkflowDefinition     = "workflow-definition"
	ResourceWorkflowStepDefinition = "workflow-step-definition"
	ResourceWorkflowInstance       = "workflow-instance"
	ResourceWorkflowExecution      = "workflow-execution"
	ResourceStepExecution          = "step-execution"
	ResourceRoleAssignment         = "role-assignment"
	ResourceControlRelationship    = "control-relationship"

	// Actions. read/create/update/delete are the CRUD verbs; the rest are resource-specific
	// (promote → risk; ingest → heartbeat/agent; register → agent; trigger → digest;
	// execute → import). ActionManage is the admin umbrella.
	ActionManage  = "manage"
	ActionRead    = "read"
	ActionCreate  = "create"
	ActionUpdate  = "update"
	ActionDelete  = "delete"
	ActionPromote = "promote"
	ActionIngest  = "ingest"
	ActionExecute = "execute"
	ActionTrigger = "trigger"
)
