// Package regocheck runs the OPA-dependent checks on inline policy bundles. It is separate
// from agentconfig so that importing agentconfig (types, merge, classify, wire) never
// compiles OPA. The API handlers and the agent import it; sdk/ does not.
//
// The check is parse-level and ADVISORY (R20, R54): it catches parse errors, direct calls to
// denied builtins and cheaply detectable `with ... as <denied>` replacements, and its errors
// still block an API save (422). It is not the security boundary: indirect use (a vendor
// helper wrapping http.send) is caught by the agent, which walks every rule reachable from
// authored rules in the compiled graph. No compile runs here because the API lacks the
// extends trees.
//
// It also runs the static policy contract check (policyeval.CheckContract, R63) on the
// authored modules: a package must have a title, and literal values of the contract keys
// must have the right types and shapes. Type and shape problems are errors. Package-level
// gaps (no title) are errors only when the bundle is self-contained; when it extends a
// source, or patches a bundle the agent's file defines (WithPartialBundles), modules the
// check cannot see may complete the package, so they are warnings.
//
// Cross-bundle imports are unsupported (R21): each policy path is compiled and loaded as its
// own bundle, exactly like policy-manager, so `import data.ccf_libs...` resolves only within
// the same bundle (including its extends tree).
package regocheck

import (
	"fmt"
	"slices"
	"strings"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/open-policy-agent/opa/v1/ast"
)

// allowedPackageRoots are the package namespaces a bundle module is expected to use.
var allowedPackageRoots = []string{"compliance_framework", "ccf_libs"}

// Codes of the parse-level checks, in PolicyError.Code. Contract problems carry the
// policyeval.Issue* codes.
const (
	CodeParse            = "rego-parse-error"
	CodeMissingRegoV1    = "missing-rego-v1-import"
	CodePackageNamespace = "package-namespace"
	CodeForbiddenBuiltin = "forbidden-builtin"
)

// completable are the contract codes for what a package lacks as a whole. Modules this
// check cannot see (an extends tree, the file part of a patched bundle) may supply it.
var completable = []string{policyeval.IssueMissingTitle}

// Option tunes ValidateModules and ValidatePolicyBundles.
type Option func(*options)

type options struct {
	partial map[string]bool
}

// WithPartialBundles names bundles whose modules are only part of the bundle: an overlay
// patching a bundle the agent's config file defines. Their package-level contract gaps are
// warnings, as for bundles that extend a source.
func WithPartialBundles(names ...string) Option {
	return func(o *options) {
		for _, name := range names {
			o.partial[name] = true
		}
	}
}

// ValidatePolicyBundles = agentconfig.ValidateBundles(b) + ValidateModules(b). The result is
// in deterministic order: bundle, path, row, col.
func ValidatePolicyBundles(b map[string]*agentconfig.PolicyBundle, opts ...Option) []agentconfig.PolicyError {
	out := agentconfig.ValidateBundles(b)
	out = append(out, ValidateModules(b, opts...)...)
	agentconfig.SortPolicyErrors(out)
	return out
}

// ValidateModules runs the Rego checks on every .rego module (tests included) without the
// bundle-shape checks:
//   - parse as Rego v1; each parse error is an error with its row and col;
//   - a warning when the module lacks `import rego.v1` (plugins built against OPA v0 would
//     parse it as v0);
//   - a warning when the package (after data.) is not, or is not under,
//     compliance_framework or ccf_libs;
//   - an error for every direct call to a builtin in policyeval.DeniedBuiltins (R19), and
//     for every `with <target> as <denied>` replacement. `with <denied> as mock` (mocking
//     the denied builtin away) is allowed;
//   - the static policy contract check (policyeval.CheckContract, R63) on the modules that
//     parse, with the severities described on the package.
func ValidateModules(b map[string]*agentconfig.PolicyBundle, opts ...Option) []agentconfig.PolicyError {
	o := options{partial: map[string]bool{}}
	for _, opt := range opts {
		opt(&o)
	}

	var out []agentconfig.PolicyError
	names := make([]string, 0, len(b))
	for name := range b {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		bundle := b[name]
		if bundle == nil {
			continue
		}
		paths := make([]string, 0, len(bundle.Modules))
		for p := range bundle.Modules {
			if strings.HasSuffix(p, ".rego") {
				paths = append(paths, p)
			}
		}
		slices.Sort(paths)
		parsed := make(map[string]*ast.Module, len(paths))
		for _, p := range paths {
			errs, module := checkModule(name, p, bundle.Modules[p])
			out = append(out, errs...)
			if module != nil {
				parsed[p] = module
			}
		}
		out = append(out, checkContract(name, parsed, bundle.Extends != nil || o.partial[name])...)
	}
	agentconfig.SortPolicyErrors(out)
	return out
}

// checkContract runs the static contract check on one bundle's parsed modules. incomplete
// means modules outside this set may complete its packages.
func checkContract(bundle string, modules map[string]*ast.Module, incomplete bool) []agentconfig.PolicyError {
	issues := policyeval.CheckContract(modules)
	out := make([]agentconfig.PolicyError, 0, len(issues))
	for _, issue := range issues {
		e := agentconfig.PolicyError{
			Bundle:   bundle,
			Path:     issue.File,
			Row:      issue.Row,
			Col:      issue.Col,
			Message:  issue.Message,
			Severity: issue.Severity,
			Code:     issue.Code,
		}
		if incomplete && e.Severity == agentconfig.SeverityError && slices.Contains(completable, issue.Code) {
			e.Severity = agentconfig.SeverityWarning
			e.Message += " (a warning only: modules outside this overlay, such as the extended source, may define it)"
		}
		out = append(out, e)
	}
	return out
}

// checkModule runs the parse-level checks on one module and returns the parsed module, or
// nil when it does not parse.
func checkModule(bundle, path, src string) ([]agentconfig.PolicyError, *ast.Module) {
	var out []agentconfig.PolicyError
	errAt := func(loc *ast.Location, severity, code, format string, args ...any) {
		e := agentconfig.PolicyError{Bundle: bundle, Path: path, Message: fmt.Sprintf(format, args...), Severity: severity, Code: code}
		if loc != nil {
			e.Row, e.Col = loc.Row, loc.Col
		}
		out = append(out, e)
	}

	module, err := ast.ParseModuleWithOpts(path, src, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		var astErrs ast.Errors
		switch e := err.(type) {
		case ast.Errors:
			astErrs = e
		case *ast.Error:
			astErrs = ast.Errors{e}
		}
		if len(astErrs) == 0 {
			errAt(nil, agentconfig.SeverityError, CodeParse, "%s", err.Error())
			return out, nil
		}
		for _, e := range astErrs {
			errAt(e.Location, agentconfig.SeverityError, CodeParse, "%s", e.Message)
		}
		return out, nil
	}
	if module == nil {
		errAt(nil, agentconfig.SeverityError, CodeParse, "module is empty")
		return out, nil
	}

	if !importsRegoV1(module) {
		errAt(module.Package.Location, agentconfig.SeverityWarning, CodeMissingRegoV1, "module does not `import rego.v1`; plugins built against OPA v0 would parse it as Rego v0")
	}
	if pkg := packagePath(module); !underAllowedRoot(pkg) {
		errAt(module.Package.Location, agentconfig.SeverityWarning, CodePackageNamespace, "package %s is not under %s", pkg, strings.Join(allowedPackageRoots, " or "))
	}

	type hit struct {
		row, col int
		name     string
	}
	seen := map[hit]bool{}
	report := func(loc *ast.Location, name, format string) {
		h := hit{name: name}
		if loc != nil {
			h.row, h.col = loc.Row, loc.Col
		}
		if seen[h] {
			return
		}
		seen[h] = true
		errAt(loc, agentconfig.SeverityError, CodeForbiddenBuiltin, format, name)
	}

	ast.WalkTerms(module, func(t *ast.Term) bool {
		if call, ok := t.Value.(ast.Call); ok && len(call) > 0 {
			if name := call[0].String(); isDenied(name) {
				report(t.Location, name, "call to forbidden builtin %s")
			}
		}
		return false
	})
	ast.WalkExprs(module, func(e *ast.Expr) bool {
		if e.IsCall() {
			if op := e.Operator(); op != nil {
				if name := op.String(); isDenied(name) {
					report(e.Location, name, "call to forbidden builtin %s")
				}
			}
		}
		for _, w := range e.With {
			if w == nil || w.Value == nil {
				continue
			}
			var name string
			switch v := w.Value.Value.(type) {
			case ast.Ref:
				name = v.String()
			case ast.Call:
				if len(v) > 0 {
					name = v[0].String()
				}
			}
			if isDenied(name) {
				loc := w.Location
				if loc == nil {
					loc = e.Location
				}
				report(loc, name, "forbidden builtin %s used as a with replacement")
			}
		}
		return false
	})
	return out, module
}

func isDenied(name string) bool {
	return name != "" && slices.Contains(policyeval.DeniedBuiltins, name)
}

func importsRegoV1(m *ast.Module) bool {
	for _, imp := range m.Imports {
		if imp != nil && imp.Path != nil && imp.Path.String() == "rego.v1" {
			return true
		}
	}
	return false
}

// packagePath returns the module package without the leading "data.".
func packagePath(m *ast.Module) string {
	if m.Package == nil {
		return ""
	}
	return strings.TrimPrefix(m.Package.Path.String(), "data.")
}

func underAllowedRoot(pkg string) bool {
	for _, root := range allowedPackageRoots {
		if pkg == root || strings.HasPrefix(pkg, root+".") {
			return true
		}
	}
	return false
}
