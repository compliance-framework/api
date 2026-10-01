package policyeval

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/compliance-framework/api/pkg/risktemplate"
	"github.com/open-policy-agent/opa/v1/ast"
)

// The policy contract is what a compliance_framework package must produce for the agent to
// turn it into evidence and risk templates:
//
//	title          string, required unless skip_reason is set
//	description    string
//	remarks        string
//	skip_reason    string; non-empty means no evidence
//	labels         object of strings
//	violation      set of objects; id, title, description, remarks are strings
//	risk_templates array of objects (see pkg/risktemplate for the rules on each)
//
// CheckContract checks it statically on parsed modules, so problems show up before a
// bundle is deployed. ValidateResult checks it on an evaluated result. Both report Issues
// with a default severity; callers decide how much an issue weighs for their modules (the
// agent, for example, only warns about vendor packages).

// Issue severities.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Issue codes.
const (
	// IssueMissingTitle: the package has no title (static), or evaluated without one
	// (dynamic, unless skipped). Error.
	IssueMissingTitle = "missing-title"
	// IssueEmptyTitle: the title is the empty string. Warning.
	IssueEmptyTitle = "empty-title"
	// IssueConditionalTitle: every title rule has a condition and there is no default, so
	// the package may have no title. Warning.
	IssueConditionalTitle = "conditional-title"
	// IssueMissingViolation: the package has no violation rule, so it is always satisfied.
	// Warning.
	IssueMissingViolation = "missing-violation"
	// IssueContractFunction: a contract key or violation is defined as a function. Error.
	IssueContractFunction = "contract-key-function"
	// IssueContractMultiValue: a contract key is defined with `contains`. Error.
	IssueContractMultiValue = "contract-key-multi-value"
	// IssueInvalidType: a contract key has a literal value of the wrong type. Error.
	IssueInvalidType = "invalid-type"
	// IssueInvalidViolationRule: violation is an object rule (`violation[k] := v`) or a
	// complete rule that is not a collection. Error.
	IssueInvalidViolationRule = "invalid-violation-rule"
	// IssueInvalidViolation: a literal violation is not an object, or has a non-string
	// id, title, description or remarks. Error.
	IssueInvalidViolation = "invalid-violation"
	// IssueViolationMissingID: a violation has no id. Warning.
	IssueViolationMissingID = "violation-missing-id"
	// IssueInvalidRiskTemplate: a risk template breaks a rule the API enforces when the
	// agent submits it. Error.
	IssueInvalidRiskTemplate = "invalid-risk-template"
	// IssueUnknownViolationID: a risk template's violation_ids names an id no literal
	// violation of the package produces. Warning.
	IssueUnknownViolationID = "unknown-violation-id"
	// IssueDuplicatePackageModule: more than one non-test module defines the package; each
	// produces its own evidence for the whole package. Warning.
	IssueDuplicatePackageModule = "duplicate-package-module"
	// IssueNoOutput: the package evaluated to nothing. Error.
	IssueNoOutput = "no-output"
)

// Issue is one contract problem.
type Issue struct {
	File     string `json:"file,omitempty"`
	Row      int    `json:"row,omitempty"`
	Col      int    `json:"col,omitempty"`
	Package  string `json:"package,omitempty"` // without the leading "data."
	Severity string `json:"severity"`          // SeverityError | SeverityWarning
	Code     string `json:"code"`              // Issue* constants
	Message  string `json:"message"`
}

// Contract keys besides violation.
const (
	keyTitle         = "title"
	keyDescription   = "description"
	keyRemarks       = "remarks"
	keySkipReason    = "skip_reason"
	keyLabels        = "labels"
	keyRiskTemplates = "risk_templates"
	keyViolation     = "violation"
)

// violationTextKeys are the violation fields the agent decodes as strings.
var violationTextKeys = []string{"id", "title", "description", "remarks"}

// IsPolicyPackage reports whether pkg (with or without "data.") is evaluated as a policy:
// compliance_framework or a package under it.
func IsPolicyPackage(pkg string) bool {
	pkg = strings.TrimPrefix(pkg, "data.")
	return pkg == "compliance_framework" || strings.HasPrefix(pkg, "compliance_framework.")
}

// IsTestFile reports whether a module file is a test, which is never evaluated as a policy.
func IsTestFile(file string) bool {
	return strings.HasSuffix(file, "_test.rego")
}

// CheckContract checks the policy contract statically on parsed modules, keyed by file.
// Only non-test modules of policy packages are checked; modules are grouped by package, so
// a title in one module satisfies the package. Values are checked where they are literals
// (directly, through a local `x := <literal>` in the rule body, or through a constant rule
// of the package); anything computed is left to ValidateResult. Issues are sorted by file,
// row, col and code.
func CheckContract(modules map[string]*ast.Module) []Issue {
	byPackage := map[string][]contractModule{}
	for file, module := range modules {
		if module == nil || module.Package == nil || IsTestFile(file) {
			continue
		}
		pkg := strings.TrimPrefix(module.Package.Path.String(), "data.")
		if !IsPolicyPackage(pkg) {
			continue
		}
		byPackage[pkg] = append(byPackage[pkg], contractModule{file: file, module: module})
	}

	var out []Issue
	for pkg, mods := range byPackage {
		slices.SortFunc(mods, func(a, b contractModule) int { return strings.Compare(a.file, b.file) })
		c := &packageChecker{pkg: pkg, modules: mods}
		out = append(out, c.check()...)
	}
	sortIssues(out)
	return out
}

// ValidateResult checks the policy contract on an evaluated result: what the agent needs to
// record evidence, and the risk templates it would submit. Problems that stop evaluation
// (wrong value types for title, labels or violations) are already errors from Execute.
// Execute stores the issues on Result.Issues.
func ValidateResult(result Result) []Issue {
	pkg := result.Policy.Package.PurePackage()
	issue := func(severity, code, format string, args ...any) Issue {
		return Issue{File: result.Policy.File, Package: pkg, Severity: severity, Code: code, Message: fmt.Sprintf(format, args...)}
	}
	if result.EvalOutput == nil {
		return []Issue{issue(SeverityError, IssueNoOutput, "package %s produced no output", pkg)}
	}

	var out []Issue
	switch {
	case result.Title == nil && Status(result) != StatusSkipped:
		out = append(out, issue(SeverityError, IssueMissingTitle, "package %s has no title, so the agent records no evidence for it", pkg))
	case result.Title != nil && strings.TrimSpace(*result.Title) == "":
		out = append(out, issue(SeverityWarning, IssueEmptyTitle, "package %s has an empty title", pkg))
	}
	for i, v := range result.Violations {
		if v.ID == nil {
			out = append(out, issue(SeverityWarning, IssueViolationMissingID, "violation %d of package %s has no id; risk templates match violations by id", i, pkg))
		}
	}
	if raw, ok := result.Raw[keyRiskTemplates]; ok {
		entries, isArray := raw.([]any)
		if !isArray {
			out = append(out, issue(SeverityError, IssueInvalidType, "risk_templates must be an array, got %s", describe(raw)))
		} else {
			names := map[string]string{}
			for i, entry := range entries {
				label := fmt.Sprintf("risk_templates[%d]", i)
				rt := checkRiskTemplate(label, entry)
				for _, p := range rt.problems {
					out = append(out, issue(p.severity, p.code, "%s", p.message))
				}
				if p, dup := duplicateName(names, rt.name, label); dup {
					out = append(out, issue(p.severity, p.code, "%s", p.message))
				}
			}
		}
	}
	return out
}

type contractModule struct {
	file   string
	module *ast.Module
}

// problem is an issue without its location, from the value checks shared by the static
// and dynamic layers.
type problem struct {
	severity, code, message string
}

func errorf(code, format string, args ...any) problem {
	return problem{severity: SeverityError, code: code, message: fmt.Sprintf(format, args...)}
}

func warnf(code, format string, args ...any) problem {
	return problem{severity: SeverityWarning, code: code, message: fmt.Sprintf(format, args...)}
}

// packageChecker checks one policy package across its non-test modules.
type packageChecker struct {
	pkg     string
	modules []contractModule
	out     []Issue

	// consts maps package rules defined exactly once as `name := <value>` with no
	// condition to their value, so literals referenced by name can be checked.
	consts map[string]*ast.Term

	titleRules, violationRules int
	titleUnconditional         bool
	firstTitle                 *ast.Location
	firstTitleFile             string

	// producedIDs are the literal violation ids, normalized with violationIDKey;
	// idsComplete is false once a violation's id cannot be read statically.
	producedIDs map[string]bool
	idsComplete bool

	// templateIDs are the literal violation_ids of literal risk templates, by location.
	templateIDs []templateIDRef
}

type templateIDRef struct {
	id   string
	file string
	loc  *ast.Location
}

func (c *packageChecker) add(file string, loc *ast.Location, p problem) {
	issue := Issue{File: file, Package: c.pkg, Severity: p.severity, Code: p.code, Message: p.message}
	if loc != nil {
		issue.Row, issue.Col = loc.Row, loc.Col
	}
	c.out = append(c.out, issue)
}

func (c *packageChecker) check() []Issue {
	c.producedIDs = map[string]bool{}
	c.idsComplete = true
	c.collectConsts()

	for _, m := range c.modules {
		for _, rule := range m.module.Rules {
			c.checkRule(m.file, rule)
		}
	}

	first := c.modules[0]
	switch {
	case c.titleRules == 0:
		c.add(first.file, first.module.Package.Location, errorf(IssueMissingTitle,
			"package %s has no title, so the agent records no evidence for it", c.pkg))
	case !c.titleUnconditional:
		c.add(c.firstTitleFile, c.firstTitle, warnf(IssueConditionalTitle,
			"every title rule of package %s has a condition and there is no default, so the package may have no title and produce no evidence", c.pkg))
	}
	if c.violationRules == 0 {
		c.add(first.file, first.module.Package.Location, warnf(IssueMissingViolation,
			"package %s has no violation rule, so it always reports satisfied", c.pkg))
	}
	if c.idsComplete {
		for _, ref := range c.templateIDs {
			if !c.producedIDs[violationIDKey(ref.id)] {
				c.add(ref.file, ref.loc, warnf(IssueUnknownViolationID,
					"risk template violation_ids names %q, which no violation of package %s produces", ref.id, c.pkg))
			}
		}
	}
	for _, m := range c.modules[1:] {
		c.add(m.file, m.module.Package.Location, warnf(IssueDuplicatePackageModule,
			"package %s is also defined by %s; every non-test module of a package produces its own evidence, so this package would be reported %d times", c.pkg, first.file, len(c.modules)))
	}
	return c.out
}

// collectConsts records the package's unconditional single-definition constants.
func (c *packageChecker) collectConsts() {
	counts := map[string]int{}
	values := map[string]*ast.Term{}
	for _, m := range c.modules {
		for _, rule := range m.module.Rules {
			name := ruleName(rule)
			counts[name]++
			if len(rule.Head.Args) == 0 && len(rule.Head.Ref()) == 1 && rule.Head.Key == nil &&
				rule.Head.Value != nil && rule.Else == nil && unconditional(rule) {
				values[name] = rule.Head.Value
			}
		}
	}
	c.consts = map[string]*ast.Term{}
	for name, value := range values {
		if counts[name] == 1 {
			c.consts[name] = value
		}
	}
}

func (c *packageChecker) checkRule(file string, rule *ast.Rule) {
	name := ruleName(rule)
	switch name {
	case keyTitle, keyDescription, keyRemarks, keySkipReason, keyLabels, keyRiskTemplates, keyViolation:
	default:
		return
	}
	loc := rule.Head.Location
	if loc == nil {
		loc = rule.Location
	}

	if len(rule.Head.Args) > 0 {
		c.add(file, loc, errorf(IssueContractFunction,
			"%s is defined as a function, so package %s has no %s value; define it as a value", name, c.pkg, name))
		return
	}
	if name == keyViolation {
		c.violationRules++
		c.checkViolationRule(file, loc, rule)
		return
	}
	if rule.Head.Key != nil && rule.Head.Value == nil {
		c.add(file, loc, errorf(IssueContractMultiValue,
			"%s is defined with `contains`, which makes it a set; %s", name, contractShape(name)))
		if name == keyTitle {
			c.titleRules++
			c.titleUnconditional = true // reported above; don't also warn it is conditional
		}
		return
	}

	switch name {
	case keyLabels:
		c.checkLabelsRule(file, loc, rule)
	case keyRiskTemplates:
		c.checkRiskTemplatesRule(file, loc, rule)
	default:
		c.checkTextRule(file, loc, name, rule)
	}
}

func contractShape(name string) string {
	switch name {
	case keyLabels:
		return "labels must be an object of strings"
	case keyRiskTemplates:
		return "risk_templates must be an array of objects"
	default:
		return name + " must be a string"
	}
}

func (c *packageChecker) checkTextRule(file string, loc *ast.Location, name string, rule *ast.Rule) {
	if name == keyTitle {
		c.titleRules++
		if c.firstTitle == nil {
			c.firstTitle, c.firstTitleFile = loc, file
		}
	}
	if ref := rule.Head.Ref(); len(ref) > 1 {
		c.add(file, loc, errorf(IssueInvalidType, "%s makes %s an object; %s must be a string", ref, name, name))
		if name == keyTitle {
			c.titleUnconditional = true
		}
		return
	}
	for r := rule; r != nil; r = r.Else {
		if name == keyTitle && (r.Default || unconditional(r)) {
			c.titleUnconditional = true
		}
		value := c.resolve(r.Head.Value, r.Body)
		if value == nil || !isLiteral(value.Value) {
			continue
		}
		s, ok := value.Value.(ast.String)
		if !ok {
			c.add(file, termLoc(r.Head.Value, loc), errorf(IssueInvalidType, "%s must be a string, got %s", name, ast.ValueName(value.Value)))
			continue
		}
		if name == keyTitle && strings.TrimSpace(string(s)) == "" {
			c.add(file, termLoc(r.Head.Value, loc), warnf(IssueEmptyTitle, "package %s has an empty title", c.pkg))
		}
	}
}

func (c *packageChecker) checkLabelsRule(file string, loc *ast.Location, rule *ast.Rule) {
	ref := rule.Head.Ref()
	switch {
	case len(ref) > 2:
		c.add(file, loc, errorf(IssueInvalidType, "%s nests an object inside labels; labels must be an object of strings", ref))
		return
	case len(ref) == 2:
		// labels.key := value or labels[key] := value
		if key := ref[1]; isLiteral(key.Value) {
			if _, ok := key.Value.(ast.String); !ok {
				c.add(file, loc, errorf(IssueInvalidType, "label keys must be strings, got %s", ast.ValueName(key.Value)))
			}
		}
		if value := c.resolve(rule.Head.Value, rule.Body); value != nil && isLiteral(value.Value) {
			if _, ok := value.Value.(ast.String); !ok {
				c.add(file, termLoc(rule.Head.Value, loc), errorf(IssueInvalidType, "label %s must be a string, got %s", ref[1], ast.ValueName(value.Value)))
			}
		}
		return
	}
	for r := rule; r != nil; r = r.Else {
		value := c.resolve(r.Head.Value, r.Body)
		if value == nil {
			continue
		}
		at := termLoc(r.Head.Value, loc)
		switch v := value.Value.(type) {
		case ast.Object:
			v.Foreach(func(k, item *ast.Term) {
				if isLiteral(k.Value) {
					if _, ok := k.Value.(ast.String); !ok {
						c.add(file, termLoc(k, at), errorf(IssueInvalidType, "label keys must be strings, got %s", ast.ValueName(k.Value)))
						return
					}
				}
				if item = c.resolve(item, r.Body); item != nil && isLiteral(item.Value) {
					if _, ok := item.Value.(ast.String); !ok {
						c.add(file, termLoc(item, at), errorf(IssueInvalidType, "label %s must be a string, got %s", k, ast.ValueName(item.Value)))
					}
				}
			})
		case *ast.ObjectComprehension:
		default:
			if isLiteral(value.Value) || isComprehension(value.Value) {
				c.add(file, at, errorf(IssueInvalidType, "labels must be an object of strings, got %s", ast.ValueName(value.Value)))
			}
		}
	}
}

func (c *packageChecker) checkRiskTemplatesRule(file string, loc *ast.Location, rule *ast.Rule) {
	if ref := rule.Head.Ref(); len(ref) > 1 {
		c.add(file, loc, errorf(IssueInvalidType, "%s makes risk_templates an object; risk_templates must be an array of objects", ref))
		return
	}
	for r := rule; r != nil; r = r.Else {
		value := c.resolve(r.Head.Value, r.Body)
		if value == nil {
			continue
		}
		at := termLoc(r.Head.Value, loc)
		switch v := value.Value.(type) {
		case *ast.Array:
			names := map[string]string{}
			for i := 0; i < v.Len(); i++ {
				entry := v.Elem(i)
				c.checkRiskTemplateEntry(file, termLoc(entry, at), fmt.Sprintf("risk_templates[%d]", i), entry, r.Body, names)
			}
		case *ast.ArrayComprehension:
			c.checkRiskTemplateEntry(file, termLoc(v.Term, at), "risk_templates[*]", v.Term, v.Body, nil)
		default:
			if isLiteral(value.Value) || isComprehension(value.Value) {
				c.add(file, at, errorf(IssueInvalidType, "risk_templates must be an array of objects, got %s", ast.ValueName(value.Value)))
			}
		}
	}
}

// checkRiskTemplateEntry checks one entry of a literal risk_templates value. names holds
// the names used by earlier entries of the same array (nil for a comprehension).
func (c *packageChecker) checkRiskTemplateEntry(file string, loc *ast.Location, label string, entry *ast.Term, body ast.Body, names map[string]string) {
	rt := checkRiskTemplate(label, c.toValue(entry, body, 0))
	for _, p := range rt.problems {
		c.add(file, loc, p)
	}
	if names != nil {
		if p, dup := duplicateName(names, rt.name, label); dup {
			c.add(file, loc, p)
		}
	}
	for _, id := range rt.violationIDs {
		c.templateIDs = append(c.templateIDs, templateIDRef{id: id, file: file, loc: loc})
	}
}

func (c *packageChecker) checkViolationRule(file string, loc *ast.Location, rule *ast.Rule) {
	head := rule.Head
	ref := head.Ref()
	switch {
	case head.Key != nil && head.Value == nil:
		// violation contains <element> (v1), or violation[<element>] (v0 partial set).
		c.checkViolationElement(file, termLoc(head.Key, loc), head.Key, rule.Body)
	case len(ref) > 2:
		c.add(file, loc, errorf(IssueInvalidViolationRule,
			"%s nests objects inside violation; violation must be a set of objects (`violation contains {...} if { ... }`)", ref))
	case len(ref) == 2:
		// violation[<key>] := <value>, or Rego v1 violation[<element>] if { ... } (value true).
		if !isTrue(head.Value) {
			c.add(file, loc, errorf(IssueInvalidViolationRule,
				"violation is an object rule (`violation[key] := value`); the agent reads its keys as the violations and ignores the values. Use `violation contains {...} if { ... }`"))
			c.idsComplete = false
			return
		}
		c.checkViolationElement(file, termLoc(ref[1], loc), ref[1], rule.Body)
	default:
		for r := rule; r != nil; r = r.Else {
			c.checkCompleteViolation(file, loc, r)
		}
	}
}

func (c *packageChecker) checkCompleteViolation(file string, loc *ast.Location, rule *ast.Rule) {
	value := c.resolve(rule.Head.Value, rule.Body)
	if value == nil {
		c.idsComplete = false
		return
	}
	at := termLoc(rule.Head.Value, loc)
	switch v := value.Value.(type) {
	case ast.Set:
		v.Foreach(func(elem *ast.Term) { c.checkViolationElement(file, termLoc(elem, at), elem, rule.Body) })
	case *ast.Array:
		for i := 0; i < v.Len(); i++ {
			c.checkViolationElement(file, termLoc(v.Elem(i), at), v.Elem(i), rule.Body)
		}
	case *ast.SetComprehension:
		c.checkViolationElement(file, termLoc(v.Term, at), v.Term, v.Body)
	case *ast.ArrayComprehension:
		c.checkViolationElement(file, termLoc(v.Term, at), v.Term, v.Body)
	default:
		if isLiteral(value.Value) || isComprehension(value.Value) {
			c.add(file, at, errorf(IssueInvalidViolationRule,
				"violation is a complete rule with a %s value; it must be a set of objects (`violation contains {...} if { ... }`)", ast.ValueName(value.Value)))
		}
		c.idsComplete = false
	}
}

func (c *packageChecker) checkViolationElement(file string, loc *ast.Location, elem *ast.Term, body ast.Body) {
	value := c.toValue(elem, body, 0)
	for _, p := range violationProblems(value) {
		c.add(file, loc, p)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		c.idsComplete = false
		return
	}
	if id, ok := obj["id"].(string); ok {
		c.producedIDs[violationIDKey(id)] = true
	} else if _, present := obj["id"]; present {
		c.idsComplete = false
	}
}

// violationIDKey normalizes a violation id the way the API matches a risk template's
// violation_ids against a violation: trimmed and case-insensitive.
func violationIDKey(id string) string {
	return strings.ToLower(strings.TrimSpace(id))
}

// resolve follows a variable to the literal it stands for: a `v := <term>` or
// `v = <term>` in the rule body, or a constant rule of the package. Anything else is
// returned unchanged.
func (c *packageChecker) resolve(term *ast.Term, body ast.Body) *ast.Term {
	for depth := 0; term != nil && depth < 8; depth++ {
		v, ok := term.Value.(ast.Var)
		if !ok {
			return term
		}
		next := bodyBinding(v, body)
		if next == nil {
			next = c.consts[string(v)]
		}
		if next == nil {
			return term
		}
		term = next
	}
	return term
}

// toValue converts a term to a Go value as OPA would produce it, with unknownValue for
// the parts that cannot be read statically (calls, refs, unbound variables,
// comprehensions).
func (c *packageChecker) toValue(term *ast.Term, body ast.Body, depth int) any {
	if depth > 16 {
		return unknown
	}
	term = c.resolve(term, body)
	if term == nil {
		return unknown
	}
	switch v := term.Value.(type) {
	case ast.Null, ast.Boolean, ast.Number, ast.String:
		out, err := ast.JSON(v)
		if err != nil {
			return unknown
		}
		return out
	case ast.Object:
		out := map[string]any{}
		complete := true
		v.Foreach(func(k, item *ast.Term) {
			key, ok := k.Value.(ast.String)
			if !ok {
				complete = false
				return
			}
			out[string(key)] = c.toValue(item, body, depth+1)
		})
		if !complete {
			return unknown
		}
		return out
	case *ast.Array:
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			out = append(out, c.toValue(v.Elem(i), body, depth+1))
		}
		return out
	case ast.Set:
		out := make([]any, 0, v.Len())
		v.Foreach(func(item *ast.Term) { out = append(out, c.toValue(item, body, depth+1)) })
		return out
	}
	return unknown
}

// unknownValue marks a value that cannot be read statically.
type unknownValue struct{}

var unknown any = unknownValue{}

func isUnknown(v any) bool {
	_, ok := v.(unknownValue)
	return ok
}

// violationProblems checks one violation value.
func violationProblems(v any) []problem {
	if isUnknown(v) {
		return nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return []problem{errorf(IssueInvalidViolation, "a violation must be an object with id, title, description and remarks, got %s", describe(v))}
	}
	var out []problem
	for _, key := range violationTextKeys {
		item, present := obj[key]
		if !present || isUnknown(item) {
			continue
		}
		if _, ok := item.(string); !ok {
			out = append(out, errorf(IssueInvalidViolation, "violation %s must be a string, got %s", key, describe(item)))
		}
	}
	if _, present := obj["id"]; !present {
		out = append(out, warnf(IssueViolationMissingID, "violation has no id; risk templates match violations by id"))
	}
	return out
}

// riskTemplateCheck is the outcome of checking one risk template value.
type riskTemplateCheck struct {
	problems     []problem
	name         string   // "" when not a literal string
	violationIDs []string // literal ids
}

// checkRiskTemplate applies the rules the API enforces when the agent submits a risk
// template (pkg/risktemplate) to one risk_templates entry. Unknown parts are skipped.
func checkRiskTemplate(label string, v any) riskTemplateCheck {
	var out riskTemplateCheck
	if isUnknown(v) {
		return out
	}
	obj, ok := v.(map[string]any)
	if !ok {
		out.problems = append(out.problems, errorf(IssueInvalidRiskTemplate, "%s must be an object, got %s", label, describe(v)))
		return out
	}
	add := func(format string, args ...any) {
		out.problems = append(out.problems, errorf(IssueInvalidRiskTemplate, format, args...))
	}

	text := map[string]string{} // literal text fields, for the label-key check
	for _, key := range []string{"name", "title", "statement"} {
		item, present := obj[key]
		switch s, isString := item.(string); {
		case !present:
			add("%s.%s is required", label, key)
		case isUnknown(item):
		case !isString:
			add("%s.%s must be a string, got %s", label, key, describe(item))
		case strings.TrimSpace(s) == "":
			add("%s.%s is required", label, key)
		case utf8.RuneCountInString(strings.TrimSpace(s)) > risktemplate.MaxFieldLength:
			add("%s.%s must be at most %d characters", label, key, risktemplate.MaxFieldLength)
		default:
			text[key] = s
		}
	}
	if name, ok := text["name"]; ok {
		out.name = strings.TrimSpace(name)
	}
	for _, key := range []string{"likelihood_hint", "impact_hint"} {
		item, present := obj[key]
		if !present || item == nil || isUnknown(item) {
			continue
		}
		s, isString := item.(string)
		switch {
		case !isString:
			add("%s.%s must be a string, got %s", label, key, describe(item))
		case !risktemplate.ValidHint(s):
			add("%s.%s %q must be one of %s, or a {{ template }}", label, key, s, strings.Join(risktemplate.RiskLevels, ", "))
		default:
			text[key] = s
		}
	}

	if ids, ok := arrayField(obj, "violation_ids", label, risktemplate.MaxViolationIDs, add); ok {
		for i, id := range ids {
			switch s, isString := id.(string); {
			case isUnknown(id):
			case !isString:
				add("%s.violation_ids[%d] must be a string, got %s", label, i, describe(id))
			case strings.TrimSpace(s) == "":
				add("%s.violation_ids[%d] must not be empty", label, i)
			default:
				out.violationIDs = append(out.violationIDs, strings.TrimSpace(s))
			}
		}
	}

	if refs, ok := arrayField(obj, "threat_refs", label, risktemplate.MaxThreatRefs, add); ok {
		seen := map[string]bool{}
		for i, ref := range refs {
			at := fmt.Sprintf("%s.threat_refs[%d]", label, i)
			fields, ok := objectItem(ref, at, add)
			if !ok {
				continue
			}
			system := requiredString(fields, "system", at, add)
			id := requiredString(fields, "external_id", at, add)
			requiredString(fields, "title", at, add)
			if system != "" && id != "" {
				key := system + "|" + id
				if seen[key] {
					add("%s duplicates system %q and external_id %q", at, system, id)
				}
				seen[key] = true
			}
		}
	}

	// schemaKnown is false when the label schema cannot be read completely, so the checks
	// against it are skipped rather than guessed.
	schemaKeys, schemaKnown := map[string]bool{}, true
	if item, present := obj["label_schema"]; present && item != nil {
		schema, ok := arrayField(obj, "label_schema", label, risktemplate.MaxLabelSchemaItems, add)
		schemaKnown = ok
		for i, field := range schema {
			at := fmt.Sprintf("%s.label_schema[%d]", label, i)
			fields, ok := objectItem(field, at, add)
			if !ok || isUnknown(fields["key"]) {
				schemaKnown = false
				continue
			}
			key := requiredString(fields, "key", at, add)
			if key == "" {
				continue
			}
			if schemaKeys[key] {
				add("%s.label_schema has duplicate key %q", label, key)
			}
			schemaKeys[key] = true
		}
	}

	if keys, ok := arrayField(obj, "dedupe_label_keys", label, risktemplate.MaxDedupeLabelKeys, add); ok && len(keys) > 0 {
		if schemaKnown && len(schemaKeys) == 0 {
			add("%s.dedupe_label_keys requires a non-empty label_schema", label)
		} else {
			seen := map[string]bool{}
			for i, k := range keys {
				switch s, isString := k.(string); {
				case isUnknown(k):
				case !isString:
					add("%s.dedupe_label_keys[%d] must be a string, got %s", label, i, describe(k))
				case strings.TrimSpace(s) == "":
					add("%s.dedupe_label_keys[%d] must not be empty", label, i)
				case seen[strings.TrimSpace(s)]:
					add("%s.dedupe_label_keys has duplicate key %q", label, strings.TrimSpace(s))
				default:
					seen[strings.TrimSpace(s)] = true
					if schemaKnown && !schemaKeys[strings.TrimSpace(s)] {
						add("%s.dedupe_label_keys key %q is not defined in label_schema", label, strings.TrimSpace(s))
					}
				}
			}
		}
	}

	if schemaKnown {
		for _, key := range []string{"title", "statement", "likelihood_hint", "impact_hint"} {
			s, ok := text[key]
			if !ok || !risktemplate.IsTemplated(s) {
				continue
			}
			refs, err := risktemplate.TemplateLabelKeys(s)
			if err != nil {
				add("%s.%s is not a valid template: %v", label, key, err)
				continue
			}
			for _, ref := range sortedKeys(refs) {
				if !schemaKeys[ref] {
					add("%s.%s references label %q, which is not in label_schema", label, key, ref)
				}
			}
		}
	}

	if item, present := obj["remediation"]; present && item != nil && !isUnknown(item) {
		at := label + ".remediation"
		if fields, ok := objectItem(item, at, add); ok {
			requiredString(fields, "title", at, add)
			if tasks, ok := arrayField(fields, "tasks", at, risktemplate.MaxRemediationTasks, add); ok {
				for i, task := range tasks {
					taskAt := fmt.Sprintf("%s.tasks[%d]", at, i)
					if taskFields, ok := objectItem(task, taskAt, add); ok {
						requiredString(taskFields, "title", taskAt, add)
					}
				}
			}
		}
	}
	return out
}

// duplicateName records a risk template name and reports a repeat: the agent derives each
// template's ID from its name, package and file, so two templates with one name collide.
func duplicateName(seen map[string]string, name, label string) (problem, bool) {
	if name == "" {
		return problem{}, false
	}
	if first, dup := seen[name]; dup {
		return errorf(IssueInvalidRiskTemplate, "%s.name %q is already used by %s; names must be unique within a package", label, name, first), true
	}
	seen[name] = label
	return problem{}, false
}

// arrayField reads an optional array field. ok is false when it is absent, null, unknown
// or not an array (reported).
func arrayField(obj map[string]any, key, label string, maxItems int, add func(string, ...any)) ([]any, bool) {
	item, present := obj[key]
	if !present || item == nil || isUnknown(item) {
		return nil, false
	}
	items, ok := item.([]any)
	if !ok {
		add("%s.%s must be an array, got %s", label, key, describe(item))
		return nil, false
	}
	if len(items) > maxItems {
		add("%s.%s must contain at most %d items", label, key, maxItems)
	}
	return items, true
}

func objectItem(item any, at string, add func(string, ...any)) (map[string]any, bool) {
	if isUnknown(item) {
		return nil, false
	}
	fields, ok := item.(map[string]any)
	if !ok {
		add("%s must be an object, got %s", at, describe(item))
	}
	return fields, ok
}

// requiredString checks a required non-empty string field and returns it trimmed, or ""
// when it is missing, invalid or unknown.
func requiredString(fields map[string]any, key, at string, add func(string, ...any)) string {
	item, present := fields[key]
	s, isString := item.(string)
	switch {
	case !present:
		add("%s.%s is required", at, key)
	case isUnknown(item):
	case !isString:
		add("%s.%s must be a string, got %s", at, key, describe(item))
	case strings.TrimSpace(s) == "":
		add("%s.%s is required", at, key)
	case utf8.RuneCountInString(strings.TrimSpace(s)) > risktemplate.MaxFieldLength:
		add("%s.%s must be at most %d characters", at, key, risktemplate.MaxFieldLength)
	default:
		return strings.TrimSpace(s)
	}
	return ""
}

// describe names the JSON type of a value as OPA returns it.
func describe(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number, float64, int, int64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

func ruleName(rule *ast.Rule) string {
	ref := rule.Head.Ref()
	if len(ref) == 0 {
		return ""
	}
	if v, ok := ref[0].Value.(ast.Var); ok {
		return string(v)
	}
	return ""
}

// unconditional reports whether a rule body is the implicit `true` of a rule without a
// condition.
func unconditional(rule *ast.Rule) bool {
	if len(rule.Body) != 1 {
		return false
	}
	expr := rule.Body[0]
	if expr.Negated || len(expr.With) > 0 {
		return false
	}
	term, ok := expr.Terms.(*ast.Term)
	return ok && isTrue(term)
}

func isTrue(term *ast.Term) bool {
	if term == nil {
		return false
	}
	b, ok := term.Value.(ast.Boolean)
	return ok && bool(b)
}

// bodyBinding returns X for a top-level `v := X`, `v = X` or `X = v` in body.
func bodyBinding(v ast.Var, body ast.Body) *ast.Term {
	for _, expr := range body {
		if expr.Negated || (!expr.IsAssignment() && !expr.IsEquality()) {
			continue
		}
		terms, ok := expr.Terms.([]*ast.Term)
		if !ok || len(terms) != 3 {
			continue
		}
		if lhs, ok := terms[1].Value.(ast.Var); ok && lhs.Equal(v) {
			return terms[2]
		}
		if rhs, ok := terms[2].Value.(ast.Var); ok && rhs.Equal(v) && expr.IsEquality() {
			return terms[1]
		}
	}
	return nil
}

// isLiteral reports whether v is a literal scalar or collection, whose type is known
// statically even when a collection's elements are computed. Calls, refs, variables and
// comprehensions are not literals.
func isLiteral(v ast.Value) bool {
	switch v.(type) {
	case ast.Null, ast.Boolean, ast.Number, ast.String, ast.Object, ast.Set, *ast.Array:
		return true
	}
	return false
}

func isComprehension(v ast.Value) bool {
	switch v.(type) {
	case *ast.ArrayComprehension, *ast.SetComprehension, *ast.ObjectComprehension:
		return true
	}
	return false
}

func termLoc(term *ast.Term, fallback *ast.Location) *ast.Location {
	if term != nil && term.Location != nil {
		return term.Location
	}
	return fallback
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortIssues(issues []Issue) {
	slices.SortStableFunc(issues, func(a, b Issue) int {
		return cmp.Or(
			strings.Compare(a.File, b.File),
			cmp.Compare(a.Row, b.Row),
			cmp.Compare(a.Col, b.Col),
			strings.Compare(a.Code, b.Code),
			strings.Compare(a.Message, b.Message),
		)
	})
}
