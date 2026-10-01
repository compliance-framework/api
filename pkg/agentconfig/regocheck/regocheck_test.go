package regocheck

import (
	"strings"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/pkg/policyeval"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bundleWith(modules map[string]string) map[string]*agentconfig.PolicyBundle {
	return map[string]*agentconfig.PolicyBundle{"b": {Modules: modules}}
}

func errorsOnly(errs []agentconfig.PolicyError) []agentconfig.PolicyError {
	var out []agentconfig.PolicyError
	for _, e := range errs {
		if e.Severity == agentconfig.SeverityError {
			out = append(out, e)
		}
	}
	return out
}

// header starts a module that meets the policy contract's package-level rules, so the
// parse-level tests see only the problems they introduce.
const header = "package compliance_framework.x\n\nimport rego.v1\n\ntitle := \"t\"\n\n"

func TestValidModuleHasNoFindings(t *testing.T) {
	errs := ValidatePolicyBundles(bundleWith(map[string]string{
		"a.rego": header + "violation contains msg if {\n\tinput.x == 1\n\tmsg := {\"id\": \"bad\"}\n}\n",
	}))
	assert.Empty(t, errs)
}

func TestParseErrorCarriesRowAndCol(t *testing.T) {
	errs := ValidatePolicyBundles(bundleWith(map[string]string{
		"a.rego": header + "violation contains msg if {\n\tinput.x ==\n}\n",
	}))
	require.NotEmpty(t, errs)
	assert.Equal(t, agentconfig.SeverityError, errs[0].Severity)
	assert.Equal(t, "b", errs[0].Bundle)
	assert.Equal(t, "a.rego", errs[0].Path)
	assert.Greater(t, errs[0].Row, 0)
	assert.Greater(t, errs[0].Col, 0)
}

func TestDeniedBuiltinsAreErrors(t *testing.T) {
	for _, builtin := range policyeval.DeniedBuiltins {
		args := "{}"
		if builtin == "opa.runtime" {
			args = ""
		}
		cases := map[string]string{
			"direct":        "r := " + builtin + "(" + args + ")\n",
			"comprehension": "r := [x | some i in [1]; x := " + builtin + "(" + args + ")]\n",
			"function":      "f(y) := " + builtin + "(" + args + ") if { y }\n",
		}
		for name, body := range cases {
			t.Run(builtin+"/"+name, func(t *testing.T) {
				errs := errorsOnly(ValidatePolicyBundles(bundleWith(map[string]string{"a.rego": header + body})))
				require.Len(t, errs, 1, "%v", errs)
				assert.Contains(t, errs[0].Message, builtin)
				assert.Greater(t, errs[0].Row, 0)
			})
		}
		t.Run(builtin+"/test-file", func(t *testing.T) {
			errs := errorsOnly(ValidatePolicyBundles(bundleWith(map[string]string{
				"a_test.rego": header + "test_x if {\n\t" + builtin + "(" + args + ")\n}\n",
			})))
			require.Len(t, errs, 1, "%v", errs)
		})
	}
}

func TestPureBuiltinsAreAllowed(t *testing.T) {
	errs := errorsOnly(ValidatePolicyBundles(bundleWith(map[string]string{
		"a.rego": header +
			"a if trace(\"x\")\n" +
			"b := rego.parse_module(\"x.rego\", \"package x\")\n" +
			"c if net.cidr_contains(\"10.0.0.0/8\", \"10.1.1.1\")\n",
	})))
	assert.Empty(t, errs)
}

func TestWithReplacement(t *testing.T) {
	t.Run("denied as replacement value", func(t *testing.T) {
		errs := errorsOnly(ValidatePolicyBundles(bundleWith(map[string]string{
			"a.rego": header + "f(x) := x\n\nr if {\n\tf({}) with f as http.send\n}\n",
		})))
		require.Len(t, errs, 1, "%v", errs)
		assert.Contains(t, errs[0].Message, "http.send")
	}) // `with f as http.send`
	t.Run("mocking the denied builtin away", func(t *testing.T) {
		errs := errorsOnly(ValidatePolicyBundles(bundleWith(map[string]string{
			"a_test.rego": header + "mock(_) := {\"status_code\": 200}\n\ntest_x if {\n\tdata.compliance_framework.x.r with http.send as mock\n}\n",
		})))
		assert.Empty(t, errs)
	})
}

func TestWarnings(t *testing.T) {
	errs := ValidatePolicyBundles(bundleWith(map[string]string{
		"a.rego": "package other\n\nallow := true\n",
	}))
	require.Len(t, errs, 2, "%v", errs)
	for _, e := range errs {
		assert.Equal(t, agentconfig.SeverityWarning, e.Severity)
	}
	msgs := errs[0].Message + errs[1].Message
	assert.Contains(t, msgs, "import rego.v1")
	assert.Contains(t, msgs, "not under")

	ok := ValidatePolicyBundles(bundleWith(map[string]string{
		"a.rego": "package ccf_libs.helpers\n\nimport rego.v1\n\nallow := true\n",
	}))
	assert.Empty(t, ok)
}

func TestShapeErrorsIncluded(t *testing.T) {
	errs := ValidatePolicyBundles(bundleWith(map[string]string{
		"foo.json": "{}",
	}))
	require.Len(t, errs, 1)
	assert.True(t, strings.Contains(errs[0].Message, "data.json"))
	assert.True(t, agentconfig.HasPolicyErrors(errs))
}

func TestDeterministicOrder(t *testing.T) {
	b := map[string]*agentconfig.PolicyBundle{
		"z": {Modules: map[string]string{"b.rego": "package x\n", "a.rego": "package x\n"}},
		"a": {Modules: map[string]string{"c.rego": "package x\n"}},
	}
	errs := ValidateModules(b)
	require.NotEmpty(t, errs)
	for i := 1; i < len(errs); i++ {
		prev, cur := errs[i-1], errs[i]
		assert.True(t, prev.Bundle < cur.Bundle || (prev.Bundle == cur.Bundle && prev.Path <= cur.Path))
	}
}

func TestContractChecks(t *testing.T) {
	const pkg = "package compliance_framework.ssh\n\nimport rego.v1\n\n"
	vendor := "ghcr.io/vendor/ssh-policies:v1"
	type want struct {
		code, severity string
	}
	cases := map[string]struct {
		bundle  *agentconfig.PolicyBundle
		partial bool
		want    []want
	}{
		// The e2e override (design §13.1): a violation but no title.
		"standalone module without a title": {
			bundle: &agentconfig.PolicyBundle{Modules: map[string]string{
				"ssh.rego": pkg + "violation contains {\"id\": \"pw\"} if { input.pw }\n",
			}},
			want: []want{{policyeval.IssueMissingTitle, agentconfig.SeverityError}},
		},
		"extends: the vendor modules may define the title": {
			bundle: &agentconfig.PolicyBundle{Extends: &vendor, Modules: map[string]string{
				"ssh.rego": pkg + "violation contains {\"id\": \"pw\"} if { input.pw }\n",
			}},
			want: []want{{policyeval.IssueMissingTitle, agentconfig.SeverityWarning}},
		},
		"patch of a file-defined bundle: the file may define the title": {
			bundle: &agentconfig.PolicyBundle{Modules: map[string]string{
				"ssh.rego": pkg + "violation contains {\"id\": \"pw\"} if { input.pw }\n",
			}},
			partial: true,
			want:    []want{{policyeval.IssueMissingTitle, agentconfig.SeverityWarning}},
		},
		"body-less override skeleton": {
			bundle: &agentconfig.PolicyBundle{Extends: &vendor, Modules: map[string]string{"ssh.rego": pkg}},
			want: []want{
				{policyeval.IssueMissingTitle, agentconfig.SeverityWarning},
				{policyeval.IssueMissingViolation, agentconfig.SeverityWarning},
			},
		},
		"shape errors block even when extending": {
			bundle: &agentconfig.PolicyBundle{Extends: &vendor, Modules: map[string]string{
				"ssh.rego": pkg + "title := 1\nviolation[k] := {\"id\": k} if { k := \"pw\" }\nlabels := {\"a\": 1}\n",
			}},
			want: []want{
				{policyeval.IssueInvalidType, agentconfig.SeverityError},
				{policyeval.IssueInvalidViolationRule, agentconfig.SeverityError},
				{policyeval.IssueInvalidType, agentconfig.SeverityError},
			},
		},
		"risk template errors block": {
			bundle: &agentconfig.PolicyBundle{Modules: map[string]string{
				"ssh.rego": pkg + "title := \"t\"\nviolation contains {\"id\": \"pw\"} if { input.pw }\nrisk_templates := [{\"name\": \"n\", \"title\": \"t\"}]\n",
			}},
			want: []want{{policyeval.IssueInvalidRiskTemplate, agentconfig.SeverityError}},
		},
		"test modules and libraries are not contract-checked": {
			bundle: &agentconfig.PolicyBundle{Modules: map[string]string{
				"ssh_test.rego": pkg + "test_x if { true }\n",
				"lib.rego":      "package ccf_libs.ssh\n\nimport rego.v1\n\nf(x) := x\n",
			}},
		},
		"modules that do not parse are left to the parse error": {
			bundle: &agentconfig.PolicyBundle{Modules: map[string]string{
				"ssh.rego": pkg + "violation contains {\"id\": \"pw\"} if {\n",
			}},
			want: []want{{CodeParse, agentconfig.SeverityError}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var opts []Option
			if tc.partial {
				opts = append(opts, WithPartialBundles("b", "other"))
			}
			errs := ValidateModules(map[string]*agentconfig.PolicyBundle{"b": tc.bundle}, opts...)
			got := make([]want, 0, len(errs))
			for _, e := range errs {
				got = append(got, want{e.Code, e.Severity})
				assert.Equal(t, "b", e.Bundle)
				assert.NotEmpty(t, e.Path)
			}
			if tc.want == nil {
				tc.want = []want{}
			}
			assert.Equal(t, tc.want, got, "%v", errs)
		})
	}
}

func TestContractErrorMapping(t *testing.T) {
	errs := ValidatePolicyBundles(bundleWith(map[string]string{
		"x.rego": "package compliance_framework.x\n\nimport rego.v1\n\nviolation contains {\"id\": \"a\"} if { input.a }\n",
	}))
	require.Len(t, errs, 1)
	assert.Equal(t, agentconfig.PolicyError{
		Bundle:   "b",
		Path:     "x.rego",
		Row:      1,
		Col:      1,
		Message:  "package compliance_framework.x has no title, so the agent records no evidence for it",
		Severity: agentconfig.SeverityError,
		Code:     policyeval.IssueMissingTitle,
	}, errs[0])
	assert.True(t, agentconfig.HasPolicyErrors(errs))

	vendor := "ghcr.io/v/p:1"
	errs = ValidatePolicyBundles(map[string]*agentconfig.PolicyBundle{"b": {Extends: &vendor, Modules: map[string]string{
		"x.rego": "package compliance_framework.x\n\nimport rego.v1\n\nviolation contains {\"id\": \"a\"} if { input.a }\n",
	}}})
	require.Len(t, errs, 1)
	assert.Equal(t, agentconfig.SeverityWarning, errs[0].Severity)
	assert.Contains(t, errs[0].Message, "a warning only")
	assert.False(t, agentconfig.HasPolicyErrors(errs))
}

func TestParseLevelCodes(t *testing.T) {
	errs := ValidatePolicyBundles(bundleWith(map[string]string{
		"a.rego": "package other\n\nr := http.send({})\n",
		"b.rego": "package compliance_framework.y\n\nimport rego.v1\n\nviolation contains {",
	}))
	codes := map[string]bool{}
	for _, e := range errs {
		codes[e.Code] = true
	}
	assert.Equal(t, map[string]bool{CodeParse: true, CodeMissingRegoV1: true, CodePackageNamespace: true, CodeForbiddenBuiltin: true}, codes)
}
