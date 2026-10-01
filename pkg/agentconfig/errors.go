package agentconfig

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// FieldError is one validation problem in a config document.
type FieldError struct {
	Path    string `json:"path"`    // RFC 6901 pointer into the snake_case config ("" = root)
	Code    string `json:"code"`    // stable machine code (R43), one of FieldCode*
	Message string `json:"message"` // human text
}

// FieldError codes (R43). The agent maps them to report reasons without its own pre-decode:
// unknown-field -> reason unknown-field; invalid-type -> invalid-type; env-missing ->
// env-missing; locked-key / forbidden-env -> forbidden-changes; everything else ->
// invalid-config.
const (
	FieldCodeUnknownField  = "unknown-field"  // key not in the schema (O4)
	FieldCodeInvalidType   = "invalid-type"   // wrong JSON type, e.g. a non-string config/labels value (O5)
	FieldCodeInvalidValue  = "invalid-value"  // right type, out of range / not in enum
	FieldCodeLockedKey     = "locked-key"     // api / daemon / remote_config in an overlay (O3)
	FieldCodeSize          = "size"           // overlay / module / bundle size limits (O2, A1.9)
	FieldCodePattern       = "pattern"        // name or module-path pattern, data-file name (O6, A1.9)
	FieldCodeCron          = "cron"           // schedule does not parse (O7)
	FieldCodeDuration      = "duration"       // interval / poll_interval
	FieldCodeSource        = "source"         // empty / inline plugin source, bad policy entry (O8)
	FieldCodeUnresolvedRef = "unresolved-ref" // inline:<b> without a bundle
	FieldCodeEnvLocation   = "env-location"   // ${env:} outside plugins.*.config (O9)
	FieldCodeForbiddenEnv  = "forbidden-env"  // ${env:CCF_API_AUTH_*} (O9)
	FieldCodeEnvMissing    = "env-missing"    // ResolveEnv: variable unset (agent only)
	FieldCodeMaskedValue   = "masked-value"   // "••••" submitted (O10)
	FieldCodeRequired      = "required"       // missing required field (api.url, plugin source, ...)
	FieldCodeConflict      = "conflict"       // data vs data.json, delete ∩ modules, delete without extends
	FieldCodeParse         = "parse"          // not a JSON object / data file does not parse
)

// ValidationErrors is a list of FieldErrors; it is the error type returned by the
// validators.
type ValidationErrors []FieldError

// Error implements error.
func (v ValidationErrors) Error() string {
	if len(v) == 0 {
		return "no validation errors"
	}
	parts := make([]string, 0, len(v))
	for _, e := range v {
		path := e.Path
		if path == "" {
			path = "/"
		}
		parts = append(parts, fmt.Sprintf("%s: %s", path, e.Message))
	}
	return strings.Join(parts, "; ")
}

// sortFieldErrors orders errors by path, then code, then message, and drops exact
// duplicates.
func sortFieldErrors(errs []FieldError) []FieldError {
	slices.SortFunc(errs, func(a, b FieldError) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Code, b.Code), strings.Compare(a.Message, b.Message))
	})
	return slices.Compact(errs)
}

// asError returns nil for an empty list and the sorted ValidationErrors otherwise.
func asError(errs []FieldError) error {
	if len(errs) == 0 {
		return nil
	}
	return ValidationErrors(sortFieldErrors(errs))
}

// Policy problem severities, shared by PolicyError and policyeval.Issue.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// PolicyError is a problem in a policy bundle. Path is the module path relative to the
// policy root (e.g. "banner.rego"), not a JSON pointer ("" = bundle-level) (R47).
type PolicyError struct {
	Bundle   string `json:"bundle"`
	Path     string `json:"path"`
	Row      int    `json:"row,omitempty"`
	Col      int    `json:"col,omitempty"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "error" | "warning"
	// Code classifies the problem when known: one of the PolicyCode* codes, or one of the
	// regocheck codes. Empty for older producers.
	Code string `json:"code,omitempty"`
}

// Policy problem codes, in PolicyError.Code and policyeval.Issue.Code. They live here, not in
// policyeval, so that code which must not compile OPA can use them. Severities are the
// defaults; callers re-weigh them (the agent, for example, only warns about vendor packages).
// See docs/policy-identity.md for the identity and plugin codes.
const (
	// Policy contract (R63), from policyeval.CheckContract (static) and
	// policyeval.ValidateResult (evaluated).

	// PolicyCodeMissingTitle: the package has no title (static), or evaluated without one
	// (dynamic, unless skipped). Error.
	PolicyCodeMissingTitle = "missing-title"
	// PolicyCodeEmptyTitle: the title is the empty string. Warning.
	PolicyCodeEmptyTitle = "empty-title"
	// PolicyCodeConditionalTitle: every title rule has a condition and there is no default,
	// so the package may have no title. Warning.
	PolicyCodeConditionalTitle = "conditional-title"
	// PolicyCodeMissingViolation: the package has no violation rule, so it is always
	// satisfied. Warning.
	PolicyCodeMissingViolation = "missing-violation"
	// PolicyCodeContractFunction: a contract key or violation is defined as a function.
	// Error.
	PolicyCodeContractFunction = "contract-key-function"
	// PolicyCodeContractMultiValue: a contract key is defined with `contains`. Error.
	PolicyCodeContractMultiValue = "contract-key-multi-value"
	// PolicyCodeInvalidType: a contract key has a literal value of the wrong type. Error.
	PolicyCodeInvalidType = "invalid-type"
	// PolicyCodeInvalidViolationRule: violation is an object rule (`violation[k] := v`) or a
	// complete rule that is not a collection. Error.
	PolicyCodeInvalidViolationRule = "invalid-violation-rule"
	// PolicyCodeInvalidViolation: a literal violation is not an object, or has a non-string
	// id, title, description or remarks. Error.
	PolicyCodeInvalidViolation = "invalid-violation"
	// PolicyCodeViolationMissingID: a violation has no id. Warning.
	PolicyCodeViolationMissingID = "violation-missing-id"
	// PolicyCodeInvalidRiskTemplate: a risk template breaks a rule the API enforces when the
	// agent submits it. Error.
	PolicyCodeInvalidRiskTemplate = "invalid-risk-template"
	// PolicyCodeUnknownViolationID: a risk template's violation_ids names an id no literal
	// violation of the package produces. Warning.
	PolicyCodeUnknownViolationID = "unknown-violation-id"
	// PolicyCodeDuplicatePackageModule: more than one non-test module defines the package;
	// each produces its own evidence for the whole package. Warning.
	PolicyCodeDuplicatePackageModule = "duplicate-package-module"
	// PolicyCodeNoOutput: the package evaluated to nothing. Error.
	PolicyCodeNoOutput = "no-output"
	// PolicyCodeInvalidPolicyID: policy_id is not a single unconditional rule whose value is
	// a non-empty string literal of at most policyeval.MaxPolicyIDLength characters (static),
	// or did not evaluate to a valid one (dynamic). Error. (A policy_id defined as a
	// function or with `contains` is reported as PolicyCodeContractFunction or
	// PolicyCodeContractMultiValue.)
	PolicyCodeInvalidPolicyID = "invalid-policy-id"
	// PolicyCodeDuplicatePolicyID: two modules checked together, or loaded by one plugin,
	// declare the same policy_id, so their evidence would share one stream. Error.
	PolicyCodeDuplicatePolicyID = "duplicate-policy-id"

	// Policy identity and plugin compatibility (R75, R76); the agent alone produces these.

	// PolicyCodeDuplicatePolicyIdentity: one plugin loads the same evidence identity (a
	// policy_id, or a package and bundle-relative file) from two policy paths, so it would
	// report it twice. Error when the overlay introduces it, warning when it comes from the
	// agent's config file.
	PolicyCodeDuplicatePolicyIdentity = "duplicate-policy-identity"
	// PolicyCodePolicyPackageChanged: an override changes the package line of the module it
	// replaces, which starts a new evidence stream. Warning.
	PolicyCodePolicyPackageChanged = "policy-package-changed"
	// PolicyCodePluginLibViolationSetUnsupported: an authored module defines violation as a
	// set (`violation contains ...`) for a plugin built against an agent library older than
	// v0.7.1, which would crash the plugin. Error; a warning when the plugin's library
	// version is unknown.
	PolicyCodePluginLibViolationSetUnsupported = "plugin-lib-violation-set-unsupported"
	// PolicyCodePluginLibPolicyIDUnsupported: an authored module declares policy_id for a
	// plugin built against an agent library without R74, which ignores it, so the module
	// starts a new path-based evidence stream. Warning.
	PolicyCodePluginLibPolicyIDUnsupported = "plugin-lib-policy-id-unsupported"
)

// HasPolicyErrors reports whether any entry has Severity "error".
func HasPolicyErrors(errs []PolicyError) bool {
	for _, e := range errs {
		if e.Severity == SeverityError {
			return true
		}
	}
	return false
}

// SortPolicyErrors orders policy errors by bundle, path, row, col, then message.
func SortPolicyErrors(errs []PolicyError) {
	slices.SortStableFunc(errs, func(a, b PolicyError) int {
		return cmp.Or(
			strings.Compare(a.Bundle, b.Bundle),
			strings.Compare(a.Path, b.Path),
			cmp.Compare(a.Row, b.Row),
			cmp.Compare(a.Col, b.Col),
			strings.Compare(a.Message, b.Message),
		)
	})
}

// bundleIssue is a bundle-shape problem with the extra detail needed to report it as a
// FieldError: the FieldError code and the pointer suffix under /policy_bundles/<bundle>.
type bundleIssue struct {
	PolicyError
	code  string // FieldCode*
	field string // pointer suffix under the bundle; "" = derived from PolicyError.Path
}

func (i bundleIssue) fieldError() FieldError {
	ptr := Pointer("policy_bundles", i.Bundle)
	switch {
	case i.field != "":
		ptr += i.field
	case i.Path != "":
		ptr = appendPointer(appendPointer(ptr, "modules"), i.Path)
	}
	return FieldError{Path: ptr, Code: i.code, Message: i.Message}
}

// issuesToFieldErrors converts error-severity bundle issues into FieldErrors.
func issuesToFieldErrors(issues []bundleIssue) []FieldError {
	var out []FieldError
	for _, i := range issues {
		if i.Severity == SeverityError {
			out = append(out, i.fieldError())
		}
	}
	return out
}
