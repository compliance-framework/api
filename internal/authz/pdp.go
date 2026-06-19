// Package authz is CCF's central authorization layer.
//
// It defines an engine-neutral Policy Decision Point (PDP) interface plus a
// driver registry (mirroring database/sql) so the authorization engine is
// pluggable: a built-in RBAC driver today, and embedded Cedar / OpenFGA /
// Permit.io / any AuthZen-compliant PDP later. The HTTP enforcement point (PEP)
// lives in internal/api/middleware and is the only thing that calls into a PDP.
//
// See the "CCF Pluggable Authorization — Design Plan" for the full model. This
// package implements Phase 1: the interface, the manifest loader and the
// builtin driver that reproduces CCF's current access rules with zero behavior
// change.
package authz

import "context"

// Subject types.
const (
	SubjectUser      = "user"
	SubjectAgent     = "agent"
	SubjectAnonymous = "anonymous"
)

// Subject is the actor a decision is made about — a user or an agent. Props
// carries the facts the PEP has gathered about the subject (e.g. email, groups,
// auth_method). Drivers must treat a missing prop as "unknown", never as a
// grant.
type Subject struct {
	Type  string // "user", "agent" or "anonymous"
	ID    string // stable identifier (user email / agent client id)
	Props map[string]any
}

// Resource is the thing being acted upon. Type matches a resource declared in
// the manifest (e.g. "evidence", "admin"). ID/Props are the instance and its
// (provisional, see BCH-1319) attributes.
type Resource struct {
	Type  string
	ID    string
	Props map[string]any
}

// Decision is the result of an evaluation. Reason is for operator logs only and
// must never be echoed verbatim to clients.
type Decision struct {
	Allow  bool
	Reason string
}

// EvalRequest is a single (subject, action, resource, context) tuple, used by
// the batch Evaluations form.
type EvalRequest struct {
	Subject  Subject
	Action   string
	Resource Resource
	Context  map[string]any
}

// PDP is a Policy Decision Point: given a self-contained tuple it returns an
// allow/deny decision. Implementations must be safe for concurrent use.
type PDP interface {
	// Evaluate decides whether subject s may perform action on resource r.
	// reqCtx carries request-scoped facts that are neither subject nor
	// resource attributes (e.g. whether the route permits public access).
	Evaluate(ctx context.Context, s Subject, action string, r Resource, reqCtx map[string]any) (Decision, error)

	// Evaluations is the batch form (AuthZen "evaluations"), used for list
	// filtering and UI permission hints. The returned slice is positional:
	// one Decision per request, in the same order.
	Evaluations(ctx context.Context, reqs []EvalRequest) ([]Decision, error)
}
