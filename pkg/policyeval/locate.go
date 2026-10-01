package policyeval

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// RuleLocation is where a rule is in its module: the 1-based first and last line.
type RuleLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

// ViolationRule is one `violation` rule of a package and the violations it produced.
type ViolationRule struct {
	Location   RuleLocation
	Violations []Violation
}

// locatedRulePrefix names the copies LocateViolations adds. Policies never use it.
const locatedRulePrefix = "ccf_located_violation_"

// LocateViolations reports which of pkg's `violation` rules produced which violations.
//
// OPA merges every `violation` rule of a package into one set, so the result alone does not
// say where a violation came from. Each rule is copied under its own name, the copies are
// evaluated alongside the originals with the same input, data and time, and each copy's
// output is the violations its rule produced. The copies are appended after the original
// source, so the reported lines are those of the module as stored.
func LocateViolations(ctx context.Context, req EvaluateModulesRequest, pkg string) ([]ViolationRule, error) {
	packagePath := "data." + strings.TrimPrefix(pkg, "data.")

	names := make([]string, 0, len(req.Modules))
	for name := range req.Modules {
		names = append(names, name)
	}
	sort.Strings(names)

	modules := make(map[string]string, len(req.Modules))
	var rules []ViolationRule
	for _, name := range names {
		source := req.Modules[name]
		modules[name] = source

		module, err := ast.ParseModule(name, source)
		if err != nil || module == nil || module.Package.Path.String() != packagePath {
			// Evaluation already reports parse errors; other packages have no rules to locate.
			continue
		}

		var copies strings.Builder
		for _, rule := range module.Rules {
			if !isViolationRule(rule) {
				continue
			}
			text := string(rule.Location.Text)
			if !strings.HasPrefix(text, "violation") {
				continue
			}
			fmt.Fprintf(&copies, "\n\n%s%d%s", locatedRulePrefix, len(rules), strings.TrimPrefix(text, "violation"))
			rules = append(rules, ViolationRule{Location: RuleLocation{
				File:      name,
				StartLine: rule.Location.Row,
				EndLine:   rule.Location.Row + strings.Count(text, "\n"),
			}})
		}
		if copies.Len() > 0 {
			modules[name] = source + "\n" + copies.String() + "\n"
		}
	}
	if len(rules) == 0 {
		return nil, nil
	}

	evaluatedAt := req.EvaluatedAt
	opts := Options{Capabilities: SandboxCapabilities()}
	if evaluatedAt != nil {
		opts.Time = *evaluatedAt
	}
	evaluator := NewFromModules(modules, req.Data, opts)
	query, err := evaluator.PrepareForEval(ctx, rego.Query(packagePath), rego.Input(req.Input))
	if err != nil {
		return nil, err
	}
	results, err := query.Eval(ctx, evaluator.EvalOptions()...)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return rules, nil
	}
	outputs, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected package %s to evaluate to an object", packagePath)
	}

	for i := range rules {
		value, ok := outputs[fmt.Sprintf("%s%d", locatedRulePrefix, i)]
		if !ok {
			continue
		}
		entries, err := normalizeViolationEntries(value)
		if err != nil {
			return nil, err
		}
		for _, raw := range entries {
			var violation Violation
			if err := json.Unmarshal(raw, &violation); err != nil {
				return nil, fmt.Errorf("decode violation entry: %w", err)
			}
			rules[i].Violations = append(rules[i].Violations, violation)
		}
	}
	return rules, nil
}

// RulesFor returns the locations of the rules that produced violation.
func RulesFor(rules []ViolationRule, violation Violation) []RuleLocation {
	locations := []RuleLocation{}
	for _, rule := range rules {
		for _, produced := range rule.Violations {
			if reflect.DeepEqual(produced, violation) {
				locations = append(locations, rule.Location)
				break
			}
		}
	}
	return locations
}

// isViolationRule reports whether rule contributes to the package's `violation` set.
func isViolationRule(rule *ast.Rule) bool {
	ref := rule.Head.Ref()
	return len(ref) > 0 && ref[0].Equal(ast.VarTerm("violation"))
}
