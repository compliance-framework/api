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

// ValidatePolicyBundles = agentconfig.ValidateBundles(b) + ValidateModules(b). The result is
// in deterministic order: bundle, path, row, col.
func ValidatePolicyBundles(b map[string]*agentconfig.PolicyBundle) []agentconfig.PolicyError {
	out := agentconfig.ValidateBundles(b)
	out = append(out, ValidateModules(b)...)
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
//     the denied builtin away) is allowed.
func ValidateModules(b map[string]*agentconfig.PolicyBundle) []agentconfig.PolicyError {
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
		for _, p := range paths {
			out = append(out, checkModule(name, p, bundle.Modules[p])...)
		}
	}
	agentconfig.SortPolicyErrors(out)
	return out
}

func checkModule(bundle, path, src string) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	errAt := func(loc *ast.Location, severity, format string, args ...any) {
		e := agentconfig.PolicyError{Bundle: bundle, Path: path, Message: fmt.Sprintf(format, args...), Severity: severity}
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
			errAt(nil, agentconfig.SeverityError, "%s", err.Error())
			return out
		}
		for _, e := range astErrs {
			errAt(e.Location, agentconfig.SeverityError, "%s", e.Message)
		}
		return out
	}
	if module == nil {
		errAt(nil, agentconfig.SeverityError, "module is empty")
		return out
	}

	if !importsRegoV1(module) {
		errAt(module.Package.Location, agentconfig.SeverityWarning, "module does not `import rego.v1`; plugins built against OPA v0 would parse it as Rego v0")
	}
	if pkg := packagePath(module); !underAllowedRoot(pkg) {
		errAt(module.Package.Location, agentconfig.SeverityWarning, "package %s is not under %s", pkg, strings.Join(allowedPackageRoots, " or "))
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
		errAt(loc, agentconfig.SeverityError, format, name)
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
	return out
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
