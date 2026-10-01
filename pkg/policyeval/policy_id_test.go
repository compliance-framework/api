package policyeval

import (
	"path"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeedPath(t *testing.T) {
	const (
		vendorPath = ".compliance-framework/policies/compliance-framework/plugin-local-ssh-policies/v0.2.0/policies"
		inlinePath = "/app/.compliance-framework/state/local-dev/inline/ssh/current/bundle"
	)
	cases := map[string]struct {
		id, file, path     string
		wantFile, wantPath string
	}{
		"no id keeps the legacy relative pair": {
			"", vendorPath + "/ssh_deny_password_auth.rego", vendorPath,
			vendorPath + "/ssh_deny_password_auth.rego", vendorPath,
		},
		"no id keeps the legacy absolute pair": {
			"", inlinePath + "/ssh/root.rego", inlinePath,
			inlinePath + "/ssh/root.rego", inlinePath,
		},
		"an id equal to the vendor file reproduces the vendor pair from an inline bundle": {
			vendorPath + "/ssh_deny_password_auth.rego", inlinePath + "/ssh_deny_password_auth.rego", inlinePath,
			vendorPath + "/ssh_deny_password_auth.rego", vendorPath,
		},
		"a nested bundle-relative path": {
			vendorPath + "/ssh/deny/password.rego", inlinePath + "/ssh/deny/password.rego", inlinePath,
			vendorPath + "/ssh/deny/password.rego", vendorPath,
		},
		"an opaque id": {
			"ssh-deny-password-auth", inlinePath + "/ssh_deny_password_auth.rego", inlinePath,
			"ssh-deny-password-auth", "ssh-deny-password-auth",
		},
		"an id with a different file name is used whole": {
			"bundle/other.rego", inlinePath + "/ssh.rego", inlinePath,
			"bundle/other.rego", "bundle/other.rego",
		},
		"the suffix must start at a path separator": {
			"bundle/xssh.rego", inlinePath + "/ssh.rego", inlinePath,
			"bundle/xssh.rego", "bundle/xssh.rego",
		},
		"only the nested suffix as a whole counts": {
			"bundle/password.rego", inlinePath + "/ssh/password.rego", inlinePath,
			"bundle/password.rego", "bundle/password.rego",
		},
		"a bundle/file id as the module template writes it": {
			"ssh/ssh_deny_password_auth.rego", inlinePath + "/ssh_deny_password_auth.rego", inlinePath,
			"ssh/ssh_deny_password_auth.rego", "ssh",
		},
		"a relative id for an absolute path": {
			"policies/root.rego", "/abs/bundle/root.rego", "/abs/bundle",
			"policies/root.rego", "policies",
		},
		"an absolute id for a relative path": {
			"/abs/bundle/root.rego", "bundle/root.rego", "bundle",
			"/abs/bundle/root.rego", "/abs/bundle",
		},
		"a file outside the policy path gives no relative path": {
			"x/root.rego", "/other/root.rego", "/abs/bundle",
			"x/root.rego", "x/root.rego",
		},
		"the file is not cleaned (OPA gives it clean)": {
			"bundle/root.rego", "./bundle/root.rego", "bundle",
			"bundle/root.rego", "bundle/root.rego",
		},
		"a policy path with a trailing slash is cleaned for the relative path": {
			"vendor/root.rego", "bundle/root.rego", "bundle/",
			"vendor/root.rego", "vendor",
		},
		"an un-cleaned id equal to the file once cleaned gives the legacy pair": {
			"./bundle//root.rego", "bundle/root.rego", "./bundle/",
			"bundle/root.rego", "./bundle/",
		},
		"a policy path of . takes the whole relative file": {
			"vendor/ssh/root.rego", "ssh/root.rego", ".",
			"vendor/ssh/root.rego", "vendor",
		},
		"a policy path of . does not take a file outside it": {
			"vendor/root.rego", "../root.rego", ".",
			"vendor/root.rego", "vendor/root.rego",
		},
		"a policy path of / takes the absolute file": {
			"vendor/root.rego", "/root.rego", "/",
			"vendor/root.rego", "vendor",
		},
		"a policy path with a trailing slash reproduces the legacy pair": {
			"bundle/root.rego", "bundle/root.rego", "bundle/",
			"bundle/root.rego", "bundle/",
		},
		"a doubled separator reproduces the legacy pair": {
			"bundle//root.rego", "bundle//root.rego", "bundle/",
			"bundle//root.rego", "bundle/",
		},
		"an empty policy path gives no relative path": {
			"x/root.rego", "root.rego", "",
			"x/root.rego", "x/root.rego",
		},
		"an invalid id counts as none": {
			strings.Repeat("a", MaxPolicyIDLength+1), "bundle/root.rego", "bundle",
			"bundle/root.rego", "bundle",
		},
		"an id that is only the separator and relative path": {
			"/root.rego", "bundle/root.rego", "bundle",
			"/root.rego", "",
		},
		"a literal un-cleaned plugin path keeps its shape in the path seed": {
			"./vendor//root.rego", "/abs/bundle/root.rego", "/abs/bundle",
			"vendor/root.rego", "./vendor/",
		},
		"an un-cleaned opaque id is cleaned for the file seed only": {
			"ssh//deny/", "/abs/bundle/root.rego", "/abs/bundle",
			"ssh/deny", "ssh//deny/",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gotFile, gotPath := SeedPath(tc.id, tc.file, tc.path)
			assert.Equal(t, tc.wantFile, gotFile, "seed file")
			assert.Equal(t, tc.wantPath, gotPath, "seed policy path")
		})
	}
}

// TestSeedPathUncleanedPolicyPath: OPA's loader gives Policy.File cleaned
// (path.Join(policyPath, rel)) while plugins seed _policy_path with the literal policy path.
// A policy_id equal to that File, or to an un-cleaned spelling of it, reproduces the legacy
// pair exactly, so the stream does not fork; other ids still find the relative path.
func TestSeedPathUncleanedPolicyPath(t *testing.T) {
	for _, policyPath := range []string{"./x", "./x/", "./a/b", "x/", "/abs/x/", "x", "/abs/x"} {
		for _, rel := range []string{"root.rego", "ssh/deny/password.rego"} {
			file := path.Join(policyPath, rel)
			name := policyPath + " " + rel

			f, p := SeedPath("", file, policyPath)
			assert.Equal(t, file, f, "no id: %s", name)
			assert.Equal(t, policyPath, p, "no id: %s", name)

			for _, id := range []string{file, policyPath + "/" + rel, strings.TrimSuffix(policyPath, "/") + "/" + rel} {
				f, p = SeedPath(id, file, policyPath)
				assert.Equal(t, file, f, "id %q: %s", id, name)
				assert.Equal(t, policyPath, p, "id %q: %s", id, name)
			}

			f, p = SeedPath("vendor/policies/"+rel, file, policyPath)
			assert.Equal(t, "vendor/policies/"+rel, f, "another location: %s", name)
			assert.Equal(t, "vendor/policies", p, "another location: %s", name)

			f, p = SeedPath("ssh-deny-password-auth", file, policyPath)
			assert.Equal(t, "ssh-deny-password-auth", f, "opaque: %s", name)
			assert.Equal(t, "ssh-deny-password-auth", p, "opaque: %s", name)
		}
	}
}

// TestSeedPathLegacyRoundTrip: for a legacy pair whose path is clean (the usual case), a
// policy_id equal to the legacy file reproduces the pair exactly, wherever the policy now
// lives, and whatever the shape of the new policy path.
func TestSeedPathLegacyRoundTrip(t *testing.T) {
	for _, legacy := range []struct{ file, path string }{
		{"policies/a.rego", "policies"},
		{"/abs/policies/a.rego", "/abs/policies"},
		{"policies/nested/deep/a.rego", "policies"},
	} {
		for _, now := range []string{"/state/inline/b/current/bundle", "relative/bundle", "./relative/bundle/", legacy.path} {
			rel := strings.TrimPrefix(strings.TrimPrefix(legacy.file, legacy.path), "/")
			gotFile, gotPath := SeedPath(legacy.file, path.Join(now, rel), now)
			assert.Equal(t, legacy.file, gotFile, "%v from %s", legacy, now)
			assert.Equal(t, legacy.path, gotPath, "%v from %s", legacy, now)
		}
	}
}

// TestSeedPathLiteralPluginPathRoundTrip: a vendor plugin given an un-cleaned policy path
// seeds (OPA's cleaned file, the literal path). A policy_id built as the literal
// plugin-path + "/" + file (not path.Join) reproduces that pair exactly from an override
// in a bundle at another (clean, absolute) path.
func TestSeedPathLiteralPluginPathRoundTrip(t *testing.T) {
	const overridePath = "/app/.compliance-framework/state/local-dev/inline/ssh/current/bundle"
	for _, vendorPath := range []string{"./policies", "./policies/", "policies/", "/abs/p/", "policies", "/abs/p", "./a/b"} {
		for _, rel := range []string{"a.rego", "ssh/deny/password.rego"} {
			legacyFile, legacyPath := path.Clean(vendorPath+"/"+rel), vendorPath
			id := vendorPath + "/" + rel

			gotFile, gotPath := SeedPath(id, path.Join(overridePath, rel), overridePath)
			assert.Equal(t, legacyFile, gotFile, "seed file: %s + %s", vendorPath, rel)
			assert.Equal(t, legacyPath, gotPath, "seed policy path: %s + %s", vendorPath, rel)
		}
	}
}

func TestValidPolicyID(t *testing.T) {
	assert.True(t, ValidPolicyID("ssh-deny-password-auth"))
	assert.True(t, ValidPolicyID(strings.Repeat("é", MaxPolicyIDLength)), "the limit counts characters, not bytes")
	assert.False(t, ValidPolicyID(""))
	assert.False(t, ValidPolicyID(strings.Repeat("a", MaxPolicyIDLength+1)))
	assert.False(t, ValidPolicyID("bad\xff"))
}

func TestExecuteSetsPolicyID(t *testing.T) {
	cases := map[string]struct {
		decl   string
		wantID string
		issues []string
	}{
		"absent":           {"", "", []string{}},
		"literal":          {`policy_id := "ssh/root.rego"`, "ssh/root.rego", []string{}},
		"computed":         {`policy_id := concat("/", ["ssh", "root.rego"])`, "ssh/root.rego", []string{}},
		"empty":            {`policy_id := ""`, "", []string{"error invalid-policy-id"}},
		"not a string":     {`policy_id := 7`, "", []string{"error invalid-policy-id"}},
		"too long":         {`policy_id := "` + strings.Repeat("a", MaxPolicyIDLength+1) + `"`, "", []string{"error invalid-policy-id"}},
		"undefined at run": {`policy_id := "x" if { input.never }`, "", []string{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			results := executeModules(t, map[string]string{"policy.rego": v1Header + "title := \"t\"\nviolation contains {\"id\": \"a\"} if { input.a }\n" + tc.decl + "\n"}, map[string]any{})
			require.Len(t, results, 1)
			assert.Equal(t, tc.wantID, results[0].Policy.ID)
			assert.Equal(t, tc.issues, codes(results[0].Issues), "%v", results[0].Issues)
			if tc.decl != "" && tc.wantID != "" {
				assert.Equal(t, tc.wantID, results[0].AdditionalVariables["policy_id"], "policy_id stays in AdditionalVariables")
			}
		})
	}
}

func TestPlaybackReturnsPolicyID(t *testing.T) {
	resp, err := Evaluate(t.Context(), EvaluateRequest{
		Policy: v1Header + "title := \"t\"\npolicy_id := \"ssh/root.rego\"\nviolation contains {\"id\": \"a\"} if { input.a }\n",
		Input:  map[string]any{},
	})
	require.NoError(t, err)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "ssh/root.rego", resp.Results[0].PolicyID)
	assert.Equal(t, []Issue{}, resp.Issues)
}

func TestCheckContractPolicyID(t *testing.T) {
	const base = "title := \"t\"\nviolation contains {\"id\": \"a\"} if { input.a }\n"
	cases := map[string]struct {
		decl string
		want []string
	}{
		"absent":               {"", []string{}},
		"literal":              {`policy_id := "ssh/root.rego"`, []string{}},
		"literal with =":       {`policy_id = "ssh/root.rego"`, []string{}},
		"max length":           {`policy_id := "` + strings.Repeat("a", MaxPolicyIDLength) + `"`, []string{}},
		"empty":                {`policy_id := ""`, []string{"error invalid-policy-id"}},
		"too long":             {`policy_id := "` + strings.Repeat("a", MaxPolicyIDLength+1) + `"`, []string{"error invalid-policy-id"}},
		"number":               {`policy_id := 7`, []string{"error invalid-policy-id"}},
		"computed":             {`policy_id := concat("/", ["a", "b"])`, []string{"error invalid-policy-id"}},
		"through a constant":   {"base := \"a\"\npolicy_id := base", []string{"error invalid-policy-id"}},
		"conditional":          {`policy_id := "a" if { input.a }`, []string{"error invalid-policy-id"}},
		"else":                 {"policy_id := \"a\" if { input.a } else := \"b\"", []string{"error invalid-policy-id"}},
		"default":              {`default policy_id := "a"`, []string{"error invalid-policy-id"}},
		"object":               {`policy_id.x := "a"`, []string{"error invalid-policy-id"}},
		"defined twice":        {"policy_id := \"a\" if { input.a }\npolicy_id := \"a\" if { not input.a }", []string{"error invalid-policy-id", "error invalid-policy-id", "error invalid-policy-id"}},
		"function":             {`policy_id(x) := "a"`, []string{"error contract-key-function"}},
		"multi-value":          {`policy_id contains "a"`, []string{"error contract-key-multi-value"}},
		"unrelated rule names": {`policy_ids := 7`, []string{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			issues := checkV1(t, base+tc.decl+"\n")
			assert.Equal(t, tc.want, codes(issues), "%v", issues)
		})
	}

	t.Run("message and location", func(t *testing.T) {
		issues := checkV1(t, base+"policy_id := 7\n")
		require.Len(t, issues, 1)
		assert.Equal(t, Issue{File: "policy.rego", Row: 7, Col: 14, Package: "compliance_framework.x", Severity: SeverityError, Code: IssueInvalidPolicyID,
			Message: "policy_id must be a string literal, got number; declare it as `policy_id := \"...\"`"}, issues[0])
	})

	t.Run("duplicates across modules", func(t *testing.T) {
		issues := CheckContract(parseModules(t, ast.RegoV1, map[string]string{
			"a.rego":      "package compliance_framework.a\n\nimport rego.v1\n\n" + base + "policy_id := \"same\"\n",
			"b.rego":      "package compliance_framework.b\n\nimport rego.v1\n\n" + base + "policy_id := \"same\"\n",
			"c.rego":      "package compliance_framework.c\n\nimport rego.v1\n\n" + base + "policy_id := \"same\"\n",
			"d.rego":      "package compliance_framework.d\n\nimport rego.v1\n\n" + base + "policy_id := \"other\"\n",
			"e_test.rego": "package compliance_framework.e\n\nimport rego.v1\n\npolicy_id := \"same\"\n",
			"lib.rego":    "package ccf_libs.lib\n\nimport rego.v1\n\npolicy_id := \"same\"\n",
		}))
		require.Equal(t, []string{"error duplicate-policy-id", "error duplicate-policy-id"}, codes(issues), "%v", issues)
		assert.Equal(t, "b.rego", issues[0].File)
		assert.Equal(t, "c.rego", issues[1].File)
		assert.Equal(t, 7, issues[0].Row)
		assert.Equal(t, `policy_id "same" is also declared by package compliance_framework.a in a.rego; each policy needs its own policy_id, or their evidence shares one stream`, issues[0].Message)
	})

	t.Run("an invalid declaration is not compared", func(t *testing.T) {
		issues := CheckContract(parseModules(t, ast.RegoV1, map[string]string{
			"a.rego": "package compliance_framework.a\n\nimport rego.v1\n\n" + base + "policy_id := \"same\" if { input.a }\n",
			"b.rego": "package compliance_framework.b\n\nimport rego.v1\n\n" + base + "policy_id := \"same\"\n",
		}))
		assert.Equal(t, []string{"error invalid-policy-id"}, codes(issues), "%v", issues)
	})

	t.Run("rego v0", func(t *testing.T) {
		issues := CheckContract(parseModules(t, ast.RegoV0, map[string]string{
			"p.rego": "package compliance_framework.v0\n\ntitle := \"t\"\npolicy_id := \"v0/p.rego\"\nviolation[{\"id\": \"a\"}] { input.a }\n",
		}))
		assert.Equal(t, []string{}, codes(issues), "%v", issues)
	})
}
