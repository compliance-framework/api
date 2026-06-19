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

// Resource and action identifiers for the routes migrated in Phase 1. These mirror the
// vocabulary declared in manifest.yaml.
const (
	ResourceAdmin    = "admin"
	ResourceEvidence = "evidence"

	ActionManage = "manage"
	ActionCreate = "create"
	ActionRead   = "read"
)
