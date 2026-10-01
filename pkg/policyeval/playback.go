package policyeval

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown"
	"github.com/open-policy-agent/opa/v1/topdown/print"
)

// PolicyModuleName is the module name the request's policy source is stored under.
const PolicyModuleName = "policy.rego"

// MaxPrints caps how many print() lines one evaluation returns.
const MaxPrints = 1000

// Error codes returned in EvalError.Code besides OPA's own (rego_parse_error,
// rego_compile_error, rego_type_error, eval_conflict_error, eval_builtin_error, ...).
const (
	ErrCodeTimeout    = "eval_timeout"
	ErrCodeNoPolicies = "no_policies"
	ErrCodeEval       = "eval_error"
	ErrCodeModuleName = "invalid_module_name"
)

// EvaluateRequest is the body of POST /api/playback/evaluate.
type EvaluateRequest struct {
	// Policy is the Rego source of the policy under test, stored as module policy.rego.
	Policy string `json:"policy"`
	// Modules holds extra Rego modules the policy imports, keyed by file name.
	Modules map[string]string `json:"modules,omitempty"`
	// Input is bound to `input`. Any JSON value.
	Input any `json:"input"`
	// Data is merged into data.* exactly as the agent merges policy data.
	Data map[string]any `json:"data,omitempty"`
	// EvaluatedAt pins time.now_ns(). Defaults to now.
	EvaluatedAt *time.Time `json:"evaluatedAt,omitempty"`
}

// EvaluateResponse is the 200 body of POST /api/playback/evaluate.
type EvaluateResponse struct {
	Results []EvaluateResult `json:"results"`
	// Issues are the static policy contract problems CheckContract finds in the request's
	// modules. They never fail the request.
	Issues     []Issue  `json:"issues"`
	Prints     []string `json:"prints"`
	DurationMs int64    `json:"durationMs"`
}

// EvaluateResult is one evaluated compliance_framework package.
type EvaluateResult struct {
	Package             string            `json:"package"`
	File                string            `json:"file"`
	PolicyID            string            `json:"policyId,omitempty"` // the package's valid policy_id (R74), if any
	Status              string            `json:"status"`
	Title               *string           `json:"title"`
	Description         *string           `json:"description"`
	Remarks             *string           `json:"remarks"`
	SkipReason          *string           `json:"skipReason"`
	Labels              map[string]string `json:"labels"`
	Violations          []Violation       `json:"violations"`
	AdditionalVariables map[string]any    `json:"additionalVariables"`
	Raw                 map[string]any    `json:"raw"`
	// Error explains why the agent would not turn this result into evidence.
	Error string `json:"error,omitempty"`
	// Issues are the policy contract problems ValidateResult finds in this result.
	Issues []Issue `json:"issues"`
}

// ErrorResponse is the 422 body of POST /api/playback/evaluate.
type ErrorResponse struct {
	Errors []EvalError `json:"errors"`
}

type EvalError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	File    string `json:"file,omitempty"`
	Row     int    `json:"row,omitempty"`
	Col     int    `json:"col,omitempty"`
}

// EvalErrors is returned by Evaluate when the policy itself is at fault: it does not parse,
// compile or evaluate, times out, or contains no policies.
type EvalErrors struct {
	Errors []EvalError
}

func (e *EvalErrors) Error() string {
	if len(e.Errors) == 0 {
		return "policy evaluation failed"
	}
	return fmt.Sprintf("%s: %s", e.Errors[0].Code, e.Errors[0].Message)
}

// Evaluate runs req in the sandbox: no I/O builtins, modules only from the request, and
// the caller's context deadline as the time limit.
func Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResponse, error) {
	modules := make(map[string]string, len(req.Modules)+1)
	for name, source := range req.Modules {
		if name == "" || name == PolicyModuleName {
			return nil, &EvalErrors{Errors: []EvalError{{
				Code:    ErrCodeModuleName,
				Message: fmt.Sprintf("module name %q is empty or reserved for the policy", name),
			}}}
		}
		modules[name] = source
	}
	modules[PolicyModuleName] = req.Policy

	return EvaluateModules(ctx, EvaluateModulesRequest{
		Modules:     modules,
		Input:       req.Input,
		Data:        req.Data,
		EvaluatedAt: req.EvaluatedAt,
	})
}

// EvaluateModulesRequest evaluates a set of Rego modules as given, for example the files of
// a stored policy bundle. No module name is reserved.
type EvaluateModulesRequest struct {
	// Modules maps each module's file name to its source.
	Modules map[string]string
	// Input is bound to `input`.
	Input any
	// Data is merged into data.* exactly as the agent merges policy data.
	Data map[string]any
	// EvaluatedAt pins time.now_ns(). Defaults to now.
	EvaluatedAt *time.Time
}

// EvaluateModules runs req in the same sandbox as Evaluate.
func EvaluateModules(ctx context.Context, req EvaluateModulesRequest) (*EvaluateResponse, error) {
	started := time.Now()

	for name := range req.Modules {
		if name == "" {
			return nil, &EvalErrors{Errors: []EvalError{{Code: ErrCodeModuleName, Message: "module name is empty"}}}
		}
	}

	evaluatedAt := started
	if req.EvaluatedAt != nil {
		evaluatedAt = *req.EvaluatedAt
	}

	prints := &printCollector{}
	evaluator := NewFromModules(req.Modules, req.Data, Options{
		Capabilities: SandboxCapabilities(),
		Time:         evaluatedAt,
		PrintHook:    prints,
	})

	results, err := evaluator.Execute(ctx, req.Input)
	if err != nil {
		return nil, toEvalErrors(ctx, err)
	}
	if len(results) == 0 {
		return nil, &EvalErrors{Errors: []EvalError{{
			Code:    ErrCodeNoPolicies,
			Message: "no package under compliance_framework was found",
		}}}
	}

	response := &EvaluateResponse{
		Results: make([]EvaluateResult, 0, len(results)),
		Issues:  contractIssues(req.Modules),
		Prints:  prints.lines(),
	}
	for _, result := range results {
		response.Results = append(response.Results, toEvaluateResult(result))
	}
	response.DurationMs = time.Since(started).Milliseconds()
	return response, nil
}

// contractIssues runs the static contract check on the request's modules. Evaluation has
// already compiled them, so a module that fails to parse here is only skipped.
func contractIssues(sources map[string]string) []Issue {
	modules := make(map[string]*ast.Module, len(sources))
	for name, source := range sources {
		if module, err := ast.ParseModuleWithOpts(name, source, ast.ParserOptions{RegoVersion: ast.RegoV1}); err == nil {
			modules[name] = module
		}
	}
	issues := CheckContract(modules)
	if issues == nil {
		issues = []Issue{}
	}
	return issues
}

// MergeData deep-merges overlay into a copy of base: nested objects are merged key by key,
// and any other value in overlay replaces the one in base. This is how the agent layers its
// configured policy data over a bundle's own data documents.
func MergeData(base, overlay map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(overlay))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range overlay {
		baseMap, baseIsMap := out[key].(map[string]any)
		overlayMap, overlayIsMap := value.(map[string]any)
		if baseIsMap && overlayIsMap {
			out[key] = MergeData(baseMap, overlayMap)
			continue
		}
		out[key] = value
	}
	return out
}

func toEvaluateResult(result Result) EvaluateResult {
	out := EvaluateResult{
		Package:             result.Policy.Package.PurePackage(),
		File:                result.Policy.File,
		PolicyID:            result.Policy.ID,
		Status:              Status(result),
		Labels:              map[string]string{},
		Violations:          []Violation{},
		AdditionalVariables: map[string]any{},
		Raw:                 result.Raw,
		Issues:              result.Issues,
	}
	if out.Issues == nil {
		out.Issues = []Issue{}
	}
	if result.EvalOutput == nil {
		out.Error = "policy produced no output"
		return out
	}

	out.Title = result.Title
	out.Description = result.Description
	out.Remarks = result.Remarks
	out.SkipReason = result.SkipReason
	if result.Labels != nil {
		out.Labels = *result.Labels
	}
	out.Violations = result.Violations
	out.AdditionalVariables = result.AdditionalVariables

	// Mirrors the agent: skipped results bypass title validation, others need a title.
	if out.Status != StatusSkipped && result.Title == nil {
		out.Error = "evidence title is required"
	}
	return out
}

func toEvalErrors(ctx context.Context, err error) *EvalErrors {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &EvalErrors{Errors: []EvalError{{
			Code:    ErrCodeTimeout,
			Message: "policy evaluation exceeded the time limit",
		}}}
	}

	return &EvalErrors{Errors: flattenErrors(err)}
}

// flattenErrors unpacks OPA's error types, which may be lists of errors, into EvalErrors
// that keep each error's code and location.
func flattenErrors(err error) []EvalError {
	var regoErrs rego.Errors
	if errors.As(err, &regoErrs) {
		out := make([]EvalError, 0, len(regoErrs))
		for _, regoErr := range regoErrs {
			out = append(out, flattenErrors(regoErr)...)
		}
		return out
	}

	var astErrs ast.Errors
	if errors.As(err, &astErrs) {
		out := make([]EvalError, 0, len(astErrs))
		for _, astErr := range astErrs {
			out = append(out, fromLocation(astErr.Code, astErr.Message, astErr.Location))
		}
		return out
	}

	var astErr *ast.Error
	if errors.As(err, &astErr) {
		return []EvalError{fromLocation(astErr.Code, astErr.Message, astErr.Location)}
	}

	var topdownErr *topdown.Error
	if errors.As(err, &topdownErr) {
		return []EvalError{fromLocation(topdownErr.Code, topdownErr.Message, topdownErr.Location)}
	}

	return []EvalError{{Code: ErrCodeEval, Message: err.Error()}}
}

func fromLocation(code, message string, loc *ast.Location) EvalError {
	out := EvalError{Code: code, Message: message}
	if loc != nil {
		out.File = loc.File
		out.Row = loc.Row
		out.Col = loc.Col
	}
	return out
}

// printCollector keeps print() output, up to MaxPrints lines.
type printCollector struct {
	mu    sync.Mutex
	out   []string
	extra int
}

func (p *printCollector) Print(pctx print.Context, msg string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.out) >= MaxPrints {
		p.extra++
		return nil
	}
	if pctx.Location != nil {
		msg = fmt.Sprintf("%s:%d: %s", pctx.Location.File, pctx.Location.Row, msg)
	}
	p.out = append(p.out, msg)
	return nil
}

func (p *printCollector) lines() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := append(make([]string, 0, len(p.out)+1), p.out...)
	if p.extra > 0 {
		out = append(out, fmt.Sprintf("... %d more print lines omitted", p.extra))
	}
	return out
}
