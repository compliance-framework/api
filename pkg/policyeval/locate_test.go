package policyeval

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const locatePolicy = `package compliance_framework.ssh

title := "SSH is hardened"

violation contains {"id": "root-login"} if input.PermitRootLogin == "yes"

violation contains v if {
	some user in input.users
	not user in data.config.allowed_users
	v := {
		"id": sprintf("user-%s", [user]),
		"title": "Unexpected user",
	}
}

violation contains {"id": "password-auth"} if {
	input.PasswordAuthentication == "yes"
}

status := "checked"
`

func TestLocateViolations(t *testing.T) {
	ctx := context.Background()

	t.Run("each violation maps to the rule that produced it", func(t *testing.T) {
		req := EvaluateModulesRequest{
			Modules: map[string]string{"ssh.rego": locatePolicy},
			Input: map[string]any{
				"PermitRootLogin":        "yes",
				"PasswordAuthentication": "no",
				"users":                  []any{"deploy", "mallory"},
			},
			Data: map[string]any{"config": map[string]any{"allowed_users": []any{"deploy"}}},
		}
		rules, err := LocateViolations(ctx, req, "compliance_framework.ssh")
		require.NoError(t, err)
		require.Len(t, rules, 3)

		assert.Equal(t, RuleLocation{File: "ssh.rego", StartLine: 5, EndLine: 5}, rules[0].Location)
		assert.Equal(t, RuleLocation{File: "ssh.rego", StartLine: 7, EndLine: 14}, rules[1].Location)
		assert.Equal(t, RuleLocation{File: "ssh.rego", StartLine: 16, EndLine: 18}, rules[2].Location)

		assert.Equal(t, []Violation{{ID: new("root-login")}}, rules[0].Violations)
		assert.Equal(t, []Violation{{ID: new("user-mallory"), Title: new("Unexpected user")}}, rules[1].Violations)
		assert.Empty(t, rules[2].Violations, "a rule that did not fire produced nothing")

		assert.Equal(t, []RuleLocation{rules[1].Location}, RulesFor(rules, Violation{ID: new("user-mallory"), Title: new("Unexpected user")}))
		assert.Empty(t, RulesFor(rules, Violation{ID: new("password-auth")}))
	})

	t.Run("matches what the package evaluates to", func(t *testing.T) {
		req := EvaluateModulesRequest{
			Modules: map[string]string{"ssh.rego": locatePolicy},
			Input:   map[string]any{"PermitRootLogin": "yes", "PasswordAuthentication": "yes", "users": []any{}},
			Data:    map[string]any{"config": map[string]any{"allowed_users": []any{}}},
		}
		resp, err := EvaluateModules(ctx, req)
		require.NoError(t, err)
		rules, err := LocateViolations(ctx, req, "compliance_framework.ssh")
		require.NoError(t, err)
		for _, violation := range resp.Results[0].Violations {
			assert.Len(t, RulesFor(rules, violation), 1, *violation.ID)
		}
	})

	t.Run("a package split across files", func(t *testing.T) {
		req := EvaluateModulesRequest{
			Modules: map[string]string{
				"a.rego":      "package compliance_framework.split\n\ntitle := \"split\"\n\nviolation contains {\"id\": \"a\"} if input.a\n",
				"b.rego":      "package compliance_framework.split\n\nviolation contains {\"id\": \"b\"} if input.b\n",
				"other.rego":  "package compliance_framework.other\n\ntitle := \"other\"\n\nviolation contains {\"id\": \"other\"} if true\n",
				"lib/x.rego":  "package ccf_libs.x\n\nviolation := 1\n",
				"a_test.rego": "package compliance_framework.split_test\n\ntest_a if true\n",
			},
			Input: map[string]any{"a": true, "b": true},
		}
		rules, err := LocateViolations(ctx, req, "compliance_framework.split")
		require.NoError(t, err)
		require.Len(t, rules, 2)
		assert.Equal(t, RuleLocation{File: "a.rego", StartLine: 5, EndLine: 5}, rules[0].Location)
		assert.Equal(t, RuleLocation{File: "b.rego", StartLine: 3, EndLine: 3}, rules[1].Location)
		assert.Equal(t, []Violation{{ID: new("a")}}, rules[0].Violations)
		assert.Equal(t, []Violation{{ID: new("b")}}, rules[1].Violations)
	})

	t.Run("uses the pinned evaluation time", func(t *testing.T) {
		at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		req := EvaluateModulesRequest{
			Modules:     map[string]string{"t.rego": "package compliance_framework.t\n\ntitle := \"t\"\n\nviolation contains {\"id\": \"old\"} if time.now_ns() < time.parse_rfc3339_ns(\"2026-06-01T00:00:00Z\")\n"},
			Input:       map[string]any{},
			EvaluatedAt: &at,
		}
		rules, err := LocateViolations(ctx, req, "compliance_framework.t")
		require.NoError(t, err)
		require.Len(t, rules, 1)
		assert.Equal(t, []Violation{{ID: new("old")}}, rules[0].Violations)
	})

	t.Run("a package without violation rules", func(t *testing.T) {
		rules, err := LocateViolations(ctx, EvaluateModulesRequest{
			Modules: map[string]string{"p.rego": "package compliance_framework.p\n\ntitle := \"p\"\n"},
		}, "compliance_framework.p")
		require.NoError(t, err)
		assert.Empty(t, rules)
	})

	t.Run("runs in the sandbox", func(t *testing.T) {
		_, err := LocateViolations(ctx, EvaluateModulesRequest{
			Modules: map[string]string{"p.rego": "package compliance_framework.p\n\nviolation contains {\"id\": x} if x := http.send({\"method\": \"GET\", \"url\": \"http://example.com\"}).body\n"},
		}, "compliance_framework.p")
		assert.Error(t, err)
	})
}
