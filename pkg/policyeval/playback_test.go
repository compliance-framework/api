package policyeval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sshPolicy = `package compliance_framework.ssh_root_login

title := "Root login is disabled"
description := "sshd must not permit root login"

violation contains {"id": "root-login-enabled", "title": "Root login is enabled"} if {
	print("PermitRootLogin =", input.sshd_config.PermitRootLogin)
	input.sshd_config.PermitRootLogin == "yes"
}
`

func requireEvalErrors(t *testing.T, err error) *EvalErrors {
	t.Helper()
	var evalErrs *EvalErrors
	require.True(t, errors.As(err, &evalErrs), "want *EvalErrors, got %T: %v", err, err)
	require.NotEmpty(t, evalErrs.Errors)
	return evalErrs
}

func TestEvaluate(t *testing.T) {
	t.Run("returns interpreted and raw outcome with prints", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: sshPolicy,
			Input:  map[string]any{"sshd_config": map[string]any{"PermitRootLogin": "yes"}},
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)

		result := resp.Results[0]
		assert.Equal(t, "compliance_framework.ssh_root_login", result.Package)
		assert.Equal(t, PolicyModuleName, result.File)
		assert.Equal(t, StatusNotSatisfied, result.Status)
		assert.Equal(t, pointer("Root login is disabled"), result.Title)
		assert.Empty(t, result.Error)
		if assert.Len(t, result.Violations, 1) {
			assert.Equal(t, pointer("root-login-enabled"), result.Violations[0].ID)
		}
		assert.Contains(t, result.Raw, "violation")
		assert.Contains(t, result.Raw, "title")
		assert.Equal(t, []Issue{}, result.Issues)
		assert.Equal(t, []Issue{}, resp.Issues)

		if assert.Len(t, resp.Prints, 1) {
			assert.True(t, strings.HasPrefix(resp.Prints[0], "policy.rego:7: "), resp.Prints[0])
			assert.Contains(t, resp.Prints[0], "PermitRootLogin = yes")
		}
	})

	t.Run("passing input is satisfied", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: sshPolicy,
			Input:  map[string]any{"sshd_config": map[string]any{"PermitRootLogin": "no"}},
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		assert.Equal(t, StatusSatisfied, resp.Results[0].Status)
		assert.Empty(t, resp.Results[0].Violations)
	})

	t.Run("uses helper modules and policy data", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: `package compliance_framework.users

import data.ccf_libs.helpers

title := "Only allowed users"

violation contains {"id": user} if {
	some user in input.users
	not helpers.allowed(user)
}
`,
			Modules: map[string]string{
				"ccf_libs/helpers.rego": `package ccf_libs.helpers

allowed(user) if user in data.allowed_users
`,
			},
			Input: map[string]any{"users": []any{"deploy", "mallory"}},
			Data:  map[string]any{"allowed_users": []any{"deploy"}},
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1, "helper package must not be evaluated as a policy")
		if assert.Len(t, resp.Results[0].Violations, 1) {
			assert.Equal(t, pointer("mallory"), resp.Results[0].Violations[0].ID)
		}
	})

	t.Run("json numbers in input compare as numbers", func(t *testing.T) {
		var input any
		decoder := json.NewDecoder(strings.NewReader(`{"port": 22}`))
		decoder.UseNumber()
		require.NoError(t, decoder.Decode(&input))

		resp, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: `package compliance_framework.port

title := "SSH is not on port 22"

violation contains {"id": "default-port"} if input.port == 22
`,
			Input: input,
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		assert.Equal(t, StatusNotSatisfied, resp.Results[0].Status)
	})

	t.Run("skipped result bypasses title check", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: `package compliance_framework.skip

skip_reason := "not applicable"
`,
			Input: map[string]any{},
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		assert.Equal(t, StatusSkipped, resp.Results[0].Status)
		assert.Equal(t, pointer("not applicable"), resp.Results[0].SkipReason)
		assert.Empty(t, resp.Results[0].Error)
	})

	t.Run("missing title is returned with an error, not dropped", func(t *testing.T) {
		resp, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: `package compliance_framework.untitled

description := "no title here"
`,
			Input: map[string]any{},
		})
		require.NoError(t, err)
		require.Len(t, resp.Results, 1)
		assert.Equal(t, "evidence title is required", resp.Results[0].Error)
	})

	t.Run("evaluatedAt pins time.now_ns", func(t *testing.T) {
		pinned := time.Date(2026, time.September, 28, 10, 0, 0, 0, time.UTC)
		req := EvaluateRequest{
			Policy: `package compliance_framework.clock

title := "Certificate is valid"

violation contains {"id": "expired"} if time.now_ns() > time.parse_rfc3339_ns(input.not_after)
`,
			Input:       map[string]any{"not_after": "2026-09-29T00:00:00Z"},
			EvaluatedAt: &pinned,
		}

		for range 3 {
			resp, err := Evaluate(context.Background(), req)
			require.NoError(t, err)
			require.Len(t, resp.Results, 1)
			assert.Equal(t, StatusSatisfied, resp.Results[0].Status)
		}

		later := pinned.Add(48 * time.Hour)
		req.EvaluatedAt = &later
		resp, err := Evaluate(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, StatusNotSatisfied, resp.Results[0].Status)
	})
}

func TestEvaluateReportsContractIssues(t *testing.T) {
	resp, err := Evaluate(context.Background(), EvaluateRequest{
		Policy: `package compliance_framework.no_title

violation contains {"title": "no id"} if { input.bad }
`,
		Input: map[string]any{"bad": true},
	})
	require.NoError(t, err, "contract issues never fail the request")
	require.Len(t, resp.Results, 1)

	result := resp.Results[0]
	assert.Equal(t, "evidence title is required", result.Error)
	assert.Equal(t, []string{"error missing-title", "warning violation-missing-id"}, codes(result.Issues))
	assert.Equal(t, []string{"error missing-title", "warning violation-missing-id"}, codes(resp.Issues))
	for _, issue := range resp.Issues {
		assert.Equal(t, PolicyModuleName, issue.File)
		assert.Equal(t, "compliance_framework.no_title", issue.Package)
		assert.Positive(t, issue.Row)
	}

	body, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"issues":[{"file":"policy.rego","row":1,"col":1,"package":"compliance_framework.no_title","severity":"error","code":"missing-title"`)
}

func TestEvaluateSandbox(t *testing.T) {
	for _, call := range []string{
		`http.send({"method": "GET", "url": "http://169.254.169.254/"})`,
		`net.lookup_ip_addr("example.com")`,
		`opa.runtime()`,
	} {
		t.Run(call, func(t *testing.T) {
			_, err := Evaluate(context.Background(), EvaluateRequest{
				Policy: fmt.Sprintf(`package compliance_framework.escape

title := "escape"

leak := %s
`, call),
				Input: map[string]any{},
			})
			evalErrs := requireEvalErrors(t, err)
			assert.Equal(t, "rego_type_error", evalErrs.Errors[0].Code)
			assert.Contains(t, evalErrs.Errors[0].Message, "undefined function")
			assert.Equal(t, PolicyModuleName, evalErrs.Errors[0].File)
			assert.Equal(t, 5, evalErrs.Errors[0].Row)
		})
	}

	t.Run("unbounded comprehension hits the time limit", func(t *testing.T) {
		items := make([]any, 1000)
		for i := range items {
			items[i] = i
		}

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		started := time.Now()
		_, err := Evaluate(ctx, EvaluateRequest{
			Policy: `package compliance_framework.slow

title := sprintf("%d", [count([1 | some a in input.items; some b in input.items; some c in input.items])])
`,
			Input: map[string]any{"items": items},
		})
		evalErrs := requireEvalErrors(t, err)
		assert.Equal(t, ErrCodeTimeout, evalErrs.Errors[0].Code)
		assert.Less(t, time.Since(started), 5*time.Second, "evaluation must stop near the deadline")
	})
}

func TestEvaluateErrors(t *testing.T) {
	t.Run("parse error carries its location", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: "package compliance_framework.broken\n\ntitle := \n",
			Input:  map[string]any{},
		})
		evalErrs := requireEvalErrors(t, err)
		assert.Equal(t, "rego_parse_error", evalErrs.Errors[0].Code)
		assert.Equal(t, PolicyModuleName, evalErrs.Errors[0].File)
		assert.NotZero(t, evalErrs.Errors[0].Row)
	})

	t.Run("evaluation error is reported", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: `package compliance_framework.conflict

title := "a" if input.a
title := "b" if input.b
`,
			Input: map[string]any{"a": true, "b": true},
		})
		evalErrs := requireEvalErrors(t, err)
		assert.Equal(t, "eval_conflict_error", evalErrs.Errors[0].Code)
	})

	t.Run("no compliance_framework package", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{
			Policy: "package somewhere_else\n\ntitle := \"x\"\n",
			Input:  map[string]any{},
		})
		evalErrs := requireEvalErrors(t, err)
		assert.Equal(t, ErrCodeNoPolicies, evalErrs.Errors[0].Code)
	})

	t.Run("module may not replace the policy", func(t *testing.T) {
		_, err := Evaluate(context.Background(), EvaluateRequest{
			Policy:  sshPolicy,
			Modules: map[string]string{PolicyModuleName: "package x"},
			Input:   map[string]any{},
		})
		evalErrs := requireEvalErrors(t, err)
		assert.Equal(t, ErrCodeModuleName, evalErrs.Errors[0].Code)
	})
}

func TestPrintCollectorCapsLines(t *testing.T) {
	policy := fmt.Sprintf(`package compliance_framework.noisy

title := "noisy"

noise := [i | some i in numbers.range(1, %d); print(i)]
`, MaxPrints+5)

	resp, err := Evaluate(context.Background(), EvaluateRequest{Policy: policy, Input: map[string]any{}})
	require.NoError(t, err)
	require.Len(t, resp.Prints, MaxPrints+1)
	assert.Equal(t, "... 5 more print lines omitted", resp.Prints[MaxPrints])
}
