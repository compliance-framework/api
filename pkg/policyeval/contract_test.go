package policyeval

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const v1Header = "package compliance_framework.x\n\nimport rego.v1\n\n"

func parseModules(t *testing.T, version ast.RegoVersion, files map[string]string) map[string]*ast.Module {
	t.Helper()
	out := make(map[string]*ast.Module, len(files))
	for name, src := range files {
		m, err := ast.ParseModuleWithOpts(name, src, ast.ParserOptions{RegoVersion: version})
		require.NoError(t, err, name)
		out[name] = m
	}
	return out
}

// codes renders issues as "severity code" pairs, sorted, for compact assertions.
func codes(issues []Issue) []string {
	out := make([]string, 0, len(issues))
	for _, i := range issues {
		out = append(out, i.Severity+" "+i.Code)
	}
	slices.Sort(out)
	return out
}

func checkV1(t *testing.T, body string) []Issue {
	t.Helper()
	return CheckContract(parseModules(t, ast.RegoV1, map[string]string{"policy.rego": v1Header + body}))
}

const validRiskTemplate = `{
	"name": "password-auth",
	"title": "Password authentication on {{ .host }}",
	"statement": "SSH accepts passwords.",
	"likelihood_hint": "medium",
	"impact_hint": "{{ .impact }}",
	"violation_ids": ["password-auth"],
	"threat_refs": [{"system": "https://cwe.mitre.org", "external_id": "CWE-521", "title": "Weak passwords"}],
	"label_schema": [{"key": "host"}, {"key": "impact"}],
	"dedupe_label_keys": ["host"],
	"remediation": {"title": "Disable password auth", "tasks": [{"title": "Set PasswordAuthentication no"}]}
}`

func TestCheckContractValidPolicies(t *testing.T) {
	cases := map[string]struct {
		version ast.RegoVersion
		src     string
	}{
		"v1 partial set": {ast.RegoV1, v1Header + `
title := "SSH denies password auth"
description := "desc"
remarks := "remarks"
skip_reason := "" if { input.enabled }
labels := {"team": "platform"}
labels_extra := 1
violation contains {"id": "password-auth", "title": "Password auth enabled", "description": sprintf("%v", [input.x])} if {
	input.password_auth
}
risk_templates := [` + validRiskTemplate + `]
`},
		"v1 partial object keyed by the violation": {ast.RegoV1, v1Header + `
title := "t"
violation[{"id": "a", "title": "A"}] if { input.a }
`},
		"v1 element bound in the body": {ast.RegoV1, v1Header + `
title := "t"
violation contains v if {
	some port in input.ports
	v := {"id": "open-port", "remarks": sprintf("%d", [port])}
}
`},
		"v0 partial set": {ast.RegoV0, `package compliance_framework.x

title = "t"

violation[{"id": "a", "title": "A"}] {
	input.a
}

violation[msg] {
	msg := {"id": "b"}
}
`},
		"complete set, array and comprehensions": {ast.RegoV1, v1Header + `
title := "t"
default violation := []
violation := {{"id": "a"}} if { input.a }
else := [{"id": "b"}] if { input.b }
else := {v | some v in input.vs}
`},
		"computed values are left to evaluation": {ast.RegoV1, v1Header + `
title := concat(" ", ["a", "b"])
labels := object.union({}, input.labels)
labels_x := 1
risk_templates := data.templates
violation contains v if { some v in input.violations }
`},
		"conditional title with a default": {ast.RegoV1, v1Header + `
default title := "fallback"
title := "special" if { input.special }
violation contains {"id": "a"} if { input.a }
`},
		"conditional title with an unconditional else": {ast.RegoV1, v1Header + `
title := "special" if { input.special } else := "plain"
violation contains {"id": "a"} if { input.a }
`},
		"labels by key": {ast.RegoV1, v1Header + `
title := "t"
labels.team := "platform"
labels[k] := v if { some k, v in input.labels }
violation contains {"id": "a"} if { input.a }
`},
		"violation_ids through a constant": {ast.RegoV1, v1Header + `
title := "t"
template_violation_ids := ["ssh.password_auth_enabled"]
violation contains {"id": "ssh.password_auth_enabled"} if { input.a }
risk_templates := [{
	"name": "n",
	"title": "t",
	"statement": "s",
	"violation_ids": template_violation_ids,
}]
`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			issues := CheckContract(parseModules(t, tc.version, map[string]string{"policy.rego": tc.src}))
			assert.Empty(t, issues)
		})
	}
}

// TestCheckContractE2EMissingTitle is the module from the RC e2e (design §13.1): an
// override that keeps a violation but has no title emits no evidence.
func TestCheckContractE2EMissingTitle(t *testing.T) {
	src := `package compliance_framework.ssh_deny_password_auth

import rego.v1

violation contains {"id": "ssh-password-auth", "title": "Password authentication is enabled"} if {
	input.sshd.passwordauthentication == "yes"
}
`
	issues := CheckContract(parseModules(t, ast.RegoV1, map[string]string{"ssh_deny_password_auth.rego": src}))
	require.Len(t, issues, 1)
	assert.Equal(t, Issue{
		File:     "ssh_deny_password_auth.rego",
		Row:      1,
		Col:      1,
		Package:  "compliance_framework.ssh_deny_password_auth",
		Severity: SeverityError,
		Code:     IssueMissingTitle,
		Message:  "package compliance_framework.ssh_deny_password_auth has no title, so the agent records no evidence for it",
	}, issues[0])

	// The body-less skeleton the UI wrote (package + import only) misses both.
	issues = CheckContract(parseModules(t, ast.RegoV1, map[string]string{"s.rego": "package compliance_framework.s\n\nimport rego.v1\n"}))
	assert.Equal(t, []string{"error missing-title", "warning missing-violation"}, codes(issues))
}

func TestCheckContractIssues(t *testing.T) {
	cases := map[string]struct {
		body string
		want []string
	}{
		// title
		"title as a function": {`title(x) := x
violation contains {"id": "a"} if { input.a }`, []string{"error contract-key-function", "error missing-title"}},
		"title with contains": {`title contains "t"
violation contains {"id": "a"} if { input.a }`, []string{"error contract-key-multi-value"}},
		"title not a string": {`title := 3
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"title not a string in an else": {`title := "a" if { input.a } else := false
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"title through a local": {`title := t if { t := ["x"] }
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type", "warning conditional-title"}},
		"title as an object": {`title.text := "t"
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"empty title": {`title := " "
violation contains {"id": "a"} if { input.a }`, []string{"warning empty-title"}},
		"conditional title": {`title := "t" if { input.a }
violation contains {"id": "a"} if { input.a }`, []string{"warning conditional-title"}},

		// other text keys
		"description not a string": {`title := "t"
description := 1
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"remarks through a constant": {`title := "t"
r := {"a": 1}
remarks := r
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"skip_reason not a string": {`title := "t"
skip_reason := true if { input.skip }
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"description as a function": {`title := "t"
description(x) := x
violation contains {"id": "a"} if { input.a }`, []string{"error contract-key-function"}},

		// labels
		"labels value not a string": {`title := "t"
labels := {"a": 1, "b": "ok"}
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"labels not an object": {`title := "t"
labels := ["a"]
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"labels key value not a string": {`title := "t"
labels.a := 1
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"labels nested": {`title := "t"
labels.a.b := "x"
violation contains {"id": "a"} if { input.a }`, []string{"error invalid-type"}},
		"labels with contains": {`title := "t"
labels contains "x"
violation contains {"id": "a"} if { input.a }`, []string{"error contract-key-multi-value"}},

		// violation
		"no violation": {`title := "t"`, []string{"warning missing-violation"}},
		"violation as an object rule": {`title := "t"
violation[k] := {"id": k} if { k := "a" }`, []string{"error invalid-violation-rule"}},
		"violation as a complete string": {`title := "t"
violation := "bad"`, []string{"error invalid-violation-rule"}},
		"violation as a complete boolean": {`title := "t"
violation if { input.bad }`, []string{"error invalid-violation-rule"}},
		"violation as a complete object": {`title := "t"
violation := {"id": "a"}`, []string{"error invalid-violation-rule"}},
		"violation as a function": {`title := "t"
violation(x) := x`, []string{"error contract-key-function", "warning missing-violation"}},
		"violation nested": {`title := "t"
violation.a.b := true`, []string{"error invalid-violation-rule"}},
		"violation keyed by a string": {`title := "t"
violation["a"] if { input.a }`, []string{"error invalid-violation"}},
		"violation element not an object": {`title := "t"
violation contains "message" if { input.a }`, []string{"error invalid-violation"}},
		"violation id not a string": {`title := "t"
violation contains {"id": 1, "title": "x"} if { input.a }`, []string{"error invalid-violation"}},
		"violation title not a string": {`title := "t"
violation contains {"id": "a", "title": ["x"]} if { input.a }`, []string{"error invalid-violation"}},
		"violation id null": {`title := "t"
violation contains {"id": null} if { input.a }`, []string{"error invalid-violation"}},
		"violation without id": {`title := "t"
violation contains v if { v := {"title": "x"} }`, []string{"warning violation-missing-id"}},
		"set element without id": {`title := "t"
violation := {{"title": "x"}}`, []string{"warning violation-missing-id"}},

		// risk_templates
		"risk_templates as an object": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := {"name": "n"}`, []string{"error invalid-type"}},
		"risk_templates as a set": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := {{"name": "n", "title": "t", "statement": "s"}}`, []string{"error invalid-type"}},
		"risk_templates with contains": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates contains {"name": "n", "title": "t", "statement": "s"}`, []string{"error contract-key-multi-value"}},
		"risk template entry not an object": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := ["n"]`, []string{"error invalid-risk-template"}},
		"risk template missing required text": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": " "}]`, []string{"error invalid-risk-template", "error invalid-risk-template"}},
		"risk template bad hint": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "likelihood_hint": "severe", "impact_hint": 3}]`, []string{"error invalid-risk-template", "error invalid-risk-template"}},
		"risk template bad threat ref": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "threat_refs": [{"system": "cwe", "title": "x"}, "cwe"]}]`, []string{"error invalid-risk-template", "error invalid-risk-template"}},
		"risk template duplicate threat ref": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "threat_refs": [{"system": "cwe", "external_id": "1", "title": "x"}, {"system": "cwe", "external_id": "1", "title": "y"}]}]`, []string{"error invalid-risk-template"}},
		"dedupe keys outside the label schema": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "label_schema": [{"key": "host"}], "dedupe_label_keys": ["host", "repo"]}]`, []string{"error invalid-risk-template"}},
		"dedupe keys without a label schema": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "dedupe_label_keys": ["host"]}]`, []string{"error invalid-risk-template"}},
		"template references a label outside the schema": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "{{ .repo }}", "statement": "s", "label_schema": [{"key": "host"}]}]`, []string{"error invalid-risk-template"}},
		"duplicate risk template names": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s"}, {"name": "n", "title": "t2", "statement": "s2"}]`, []string{"error invalid-risk-template"}},
		"remediation without a title": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "remediation": {"tasks": [{}]}}]`, []string{"error invalid-risk-template", "error invalid-risk-template"}},
		"violation_ids no violation produces": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "violation_ids": ["a", "b"]}]`, []string{"warning unknown-violation-id"}},
		"violation_ids with no violation rule": {`title := "t"
risk_templates := [{"name": "n", "title": "t", "statement": "s", "violation_ids": ["a"]}]`, []string{"warning missing-violation", "warning unknown-violation-id"}},
		"violation_ids match like the API: trimmed, any case": {`title := "t"
violation contains {"id": "SSH.Password_Auth"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "violation_ids": [" ssh.password_auth "]}]`, nil},
		"violation_ids against computed ids": {`title := "t"
violation contains {"id": sprintf("port-%d", [p])} if { some p in input.ports }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "violation_ids": ["port-22"]}]`, nil},
		"violation_ids not strings": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "violation_ids": [1, ""]}]`, []string{"error invalid-risk-template", "error invalid-risk-template"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			issues := checkV1(t, tc.body)
			want := tc.want
			if want == nil {
				want = []string{}
			}
			assert.Equal(t, want, codes(issues), "%v", issues)
			for _, issue := range issues {
				assert.Equal(t, "policy.rego", issue.File)
				assert.Equal(t, "compliance_framework.x", issue.Package)
				assert.Positive(t, issue.Row, "%v", issue)
				assert.NotEmpty(t, issue.Message)
			}
		})
	}
}

func TestCheckContractMessagesAndLocations(t *testing.T) {
	issues := checkV1(t, `title := "t"
violation contains {"id": "a", "title": 1} if { input.a }
risk_templates := [{"name": "n", "title": "t", "statement": "s", "likelihood_hint": "severe"}]`)
	require.Len(t, issues, 2)
	assert.Equal(t, 6, issues[0].Row)
	assert.Equal(t, "violation title must be a string, got number", issues[0].Message)
	assert.Equal(t, 7, issues[1].Row)
	assert.Equal(t, `risk_templates[0].likelihood_hint "severe" must be one of negligible, low, moderate, high, critical, or a {{ template }}`, issues[1].Message)
}

func TestCheckContractPackages(t *testing.T) {
	t.Run("a title in another module of the package counts, but the package is reported twice", func(t *testing.T) {
		issues := CheckContract(parseModules(t, ast.RegoV1, map[string]string{
			"a.rego": v1Header + `title := "t"`,
			"b.rego": v1Header + `violation contains {"id": "a"} if { input.a }`,
		}))
		require.Equal(t, []string{"warning duplicate-package-module"}, codes(issues))
		assert.Equal(t, "b.rego", issues[0].File)
		assert.Contains(t, issues[0].Message, "also defined by a.rego")
	})

	t.Run("tests and non-policy packages are not checked", func(t *testing.T) {
		issues := CheckContract(parseModules(t, ast.RegoV1, map[string]string{
			"policy.rego":      v1Header + "title := \"t\"\nviolation contains {\"id\": \"a\"} if { input.a }\n",
			"policy_test.rego": "package compliance_framework.x\n\nimport rego.v1\n\ntest_a if { true }\n",
			"lib.rego":         "package ccf_libs.helpers\n\nimport rego.v1\n\nf(x) := x\n",
			"other_test.rego":  "package compliance_framework.only_tests\n\nimport rego.v1\n\ntest_b if { true }\n",
		}))
		assert.Empty(t, issues)
	})

	t.Run("each package is checked on its own", func(t *testing.T) {
		issues := CheckContract(parseModules(t, ast.RegoV1, map[string]string{
			"a.rego": "package compliance_framework.a\n\nimport rego.v1\n\ntitle := \"t\"\nviolation contains {\"id\": \"a\"} if { input.a }\n",
			"b.rego": "package compliance_framework.b\n\nimport rego.v1\n\nviolation contains {\"id\": \"b\"} if { input.b }\n",
			"r.rego": "package compliance_framework\n\nimport rego.v1\n\ntitle := 1\n",
		}))
		assert.Equal(t, []string{"error invalid-type", "error missing-title", "warning missing-violation"}, codes(issues))
		pkgs := map[string]bool{}
		for _, issue := range issues {
			pkgs[issue.Package] = true
		}
		assert.Equal(t, map[string]bool{"compliance_framework.b": true, "compliance_framework": true}, pkgs)
	})

	t.Run("nil modules are skipped", func(t *testing.T) {
		assert.Empty(t, CheckContract(map[string]*ast.Module{"x.rego": nil}))
		assert.Empty(t, CheckContract(nil))
	})
}

func TestIsPolicyPackage(t *testing.T) {
	assert.True(t, IsPolicyPackage("compliance_framework"))
	assert.True(t, IsPolicyPackage("data.compliance_framework.x"))
	assert.False(t, IsPolicyPackage("compliance_frameworks"))
	assert.False(t, IsPolicyPackage("ccf_libs.x"))
}

func executeModules(t *testing.T, modules map[string]string, input any) []Result {
	t.Helper()
	results, err := NewFromModules(modules, nil, Options{}).Execute(context.Background(), input)
	require.NoError(t, err)
	return results
}

func TestValidateResult(t *testing.T) {
	cases := map[string]struct {
		body  string
		input any
		want  []string
	}{
		"valid": {`title := "t"
violation contains {"id": "a"} if { input.a }
risk_templates := [` + validRiskTemplate + `]`, map[string]any{"a": true}, nil},
		"conditional title not met": {`title := "t" if { input.named }
violation contains {"id": "a"} if { input.a }`, map[string]any{}, []string{"error missing-title"}},
		"skipped without a title": {`skip_reason := "not applicable"
violation contains {"id": "a"} if { input.a }`, map[string]any{}, nil},
		"empty title": {`title := ""`, map[string]any{}, []string{"warning empty-title"}},
		"violation without id": {`title := "t"
violation contains {"title": sprintf("%v", [x])} if { some x in input.xs }`, map[string]any{"xs": []any{1, 2}}, []string{"warning violation-missing-id", "warning violation-missing-id"}},
		"risk_templates not an array": {`title := "t"
risk_templates := {"name": concat("", ["n"])}`, map[string]any{}, []string{"error invalid-type"}},
		"computed risk template missing fields": {`title := "t"
risk_templates := [{"name": concat("", ["n"]), "likelihood_hint": input.level}]`, map[string]any{"level": "extreme"}, []string{"error invalid-risk-template", "error invalid-risk-template", "error invalid-risk-template"}},
		"computed duplicate risk template names": {`title := "t"
risk_templates := [{"name": n, "title": "t", "statement": "s"} | some n in input.names]`, map[string]any{"names": []any{"n", "n"}}, []string{"error invalid-risk-template"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			results := executeModules(t, map[string]string{"policy.rego": v1Header + tc.body}, tc.input)
			require.Len(t, results, 1)
			want := tc.want
			if want == nil {
				want = []string{}
			}
			assert.Equal(t, want, codes(results[0].Issues), "%v", results[0].Issues)
			assert.Equal(t, results[0].Issues, ValidateResult(results[0]))
			for _, issue := range results[0].Issues {
				assert.Equal(t, "policy.rego", issue.File)
				assert.Equal(t, "compliance_framework.x", issue.Package)
			}
		})
	}

	t.Run("no output", func(t *testing.T) {
		issues := ValidateResult(Result{Policy: Policy{File: "p.rego", Package: "data.compliance_framework.p"}})
		assert.Equal(t, []Issue{{File: "p.rego", Package: "compliance_framework.p", Severity: SeverityError, Code: IssueNoOutput, Message: "package compliance_framework.p produced no output"}}, issues)
	})

	t.Run("duplicate names in a literal array", func(t *testing.T) {
		results := executeModules(t, map[string]string{"policy.rego": v1Header + `title := "t"
risk_templates := [{"name": "n", "title": "t", "statement": "s"}, {"name": input.n, "title": "t", "statement": "s"}]`}, map[string]any{"n": "n"})
		require.Len(t, results, 1)
		require.Equal(t, []string{"error invalid-risk-template"}, codes(results[0].Issues))
		assert.Equal(t, `risk_templates[1].name "n" is already used by risk_templates[0]; names must be unique within a package`, results[0].Issues[0].Message)
	})
}

// TestContractLayersAgree runs the same broken templates through both layers: the static
// check on literals and the dynamic check on evaluated values report the same messages.
func TestContractLayersAgree(t *testing.T) {
	for i, entry := range []string{
		`{"name": "n"}`,
		`{"name": "n", "title": "t", "statement": "s", "impact_hint": "huge"}`,
		`{"name": "n", "title": "t", "statement": "s", "label_schema": [{"key": "a"}, {"key": "a"}]}`,
		`{"name": "n", "title": "t", "statement": "s", "threat_refs": [{"system": "s", "external_id": "", "title": "x"}]}`,
		`{"name": "n", "title": "{{ .x", "statement": "s", "label_schema": [{"key": "x"}]}`,
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			src := v1Header + "title := \"t\"\nrisk_templates := [" + entry + "]\n"
			static := CheckContract(parseModules(t, ast.RegoV1, map[string]string{"policy.rego": src}))
			results := executeModules(t, map[string]string{"policy.rego": src}, map[string]any{})
			require.Len(t, results, 1)

			messages := func(issues []Issue) []string {
				var out []string
				for _, issue := range issues {
					if issue.Code == IssueInvalidRiskTemplate {
						out = append(out, issue.Message)
					}
				}
				slices.Sort(out)
				return out
			}
			require.NotEmpty(t, messages(static))
			assert.Equal(t, messages(static), messages(results[0].Issues))
			for _, m := range messages(static) {
				assert.True(t, strings.HasPrefix(m, "risk_templates[0]"), m)
			}
		})
	}
}
