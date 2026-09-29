package policyeval

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
)

func pointer[T any](v T) *T {
	return &v
}

func buildEvaluator(regoContents []byte) *Evaluator {
	return buildEvaluatorWithModules(map[string][]byte{
		"test.rego": regoContents,
	})
}

func buildEvaluatorWithModules(modules map[string][]byte) *Evaluator {
	bundleModules := make([]bundle.ModuleFile, 0, len(modules))
	for path, regoContents := range modules {
		bundleModules = append(bundleModules, bundle.ModuleFile{
			Path:   path,
			Parsed: ast.MustParseModule(string(regoContents[:])),
			Raw:    []byte(regoContents),
		})
	}

	return NewWithLoaders([]func(r *rego.Rego){
		rego.ParsedBundle("test", &bundle.Bundle{
			Modules:  bundleModules,
			Manifest: bundle.Manifest{Revision: "test", Roots: &[]string{"/"}},
		}),
	}, nil, Options{})
}

func TestEvaluator(t *testing.T) {
	t.Run("understands bundles", func(t *testing.T) {
		ctx := context.Background()

		results, err := NewFromBundlePath("testdata/001/", nil, Options{}).Execute(ctx, map[string]interface{}{})

		assert.NoError(t, err)
		assert.Equal(t, 1, len(results))
		assert.Equal(t, 0, len(results[0].Violations))
	})

	t.Run("handles violations", func(t *testing.T) {
		ctx := context.Background()

		regoContents, err := os.ReadFile("testdata/001/test_policy.rego")
		assert.NoError(t, err)

		data := map[string]interface{}{"violated": []string{"yes"}}

		results, err := buildEvaluator(regoContents).Execute(ctx, data)

		assert.NoError(t, err)
		assert.Equal(t, 1, len(results))
		assert.Equal(t, 1, len(results[0].Violations))
		assert.Equal(t, Violation{
			Title:       pointer("Violation 1"),
			Description: pointer("You have been violated."),
			Remarks:     pointer("Migrate to not being violated"),
		}, results[0].Violations[0])
	})

	t.Run("handles violations defined as a set", func(t *testing.T) {
		ctx := context.Background()

		regoContents := []byte(`package compliance_framework.set_violation

import future.keywords.contains
import future.keywords.if

violation contains {
	"title": "Violation 1",
	"description": "You have been violated.",
	"remarks": "Migrate to not being violated",
} if {
	input.violated
}
`)

		results, err := buildEvaluator(regoContents).Execute(ctx, map[string]interface{}{"violated": true})

		assert.NoError(t, err)
		assert.Equal(t, 1, len(results))
		assert.Equal(t, 1, len(results[0].Violations))
		assert.Equal(t, Violation{
			Title:       pointer("Violation 1"),
			Description: pointer("You have been violated."),
			Remarks:     pointer("Migrate to not being violated"),
		}, results[0].Violations[0])
	})

	t.Run("injects dynamic policy data as OPA data", func(t *testing.T) {
		ctx := context.Background()
		policyDir := t.TempDir()
		regoContents := []byte(`package compliance_framework.dynamic_policy_data

title := "Wget version is safe"
description := sprintf("Minimum wget version is %s", [data.allowed_versions.wget])

violation[{
	"id": "wget_version",
	"remarks": sprintf("Required wget version is %s", [data.allowed_versions.wget]),
}] if {
	input.wget != data.allowed_versions.wget
}
`)

		err := os.WriteFile(filepath.Join(policyDir, "dynamic_policy_data.rego"), regoContents, 0o644)
		assert.NoError(t, err)

		evaluator := NewFromBundlePath(policyDir, map[string]interface{}{
			"allowed_versions": map[string]interface{}{
				"wget": "1.20.3",
			},
		}, Options{})

		results, err := evaluator.Execute(ctx, map[string]interface{}{"wget": "1.19.0"})

		assert.NoError(t, err)
		if assert.Len(t, results, 1) {
			result := results[0]
			assert.Equal(t, pointer("Minimum wget version is 1.20.3"), result.Description)
			if assert.Len(t, result.Violations, 1) {
				assert.Equal(t, pointer("wget_version"), result.Violations[0].ID)
				assert.Equal(t, pointer("Required wget version is 1.20.3"), result.Violations[0].Remarks)
			}
		}
	})

	t.Run("ignores test files and packages outside compliance_framework", func(t *testing.T) {
		ctx := context.Background()

		results, err := NewFromModules(map[string]string{
			"policy.rego": `package compliance_framework.uses_lib

import data.ccf_libs.helpers

title := helpers.greeting
`,
			"helpers.rego": `package ccf_libs.helpers

greeting := "hello"
`,
			"policy_test.rego": `package compliance_framework.uses_lib_test

test_greeting if { true }
`,
		}, nil, Options{}).Execute(ctx, map[string]interface{}{})

		assert.NoError(t, err)
		if assert.Len(t, results, 1) {
			assert.Equal(t, "compliance_framework.uses_lib", results[0].Policy.Package.PurePackage())
			assert.Equal(t, pointer("hello"), results[0].Title)
		}
	})
}

func TestEvaluatorExecuteWithSkipReason(t *testing.T) {
	ctx := context.Background()

	// skip_reason set should set SkipReason field
	regoContentsSkip := []byte(`package compliance_framework.skip_test

import future.keywords.in

title := "This should be skipped"
description := "This evidence should not be produced"
skip_reason := "Invalid payload structure"

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	results, err := buildEvaluator(regoContentsSkip).Execute(ctx, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0].SkipReason, "SkipReason field should be set when policy sets skip_reason")
	assert.Equal(t, "Invalid payload structure", *results[0].SkipReason, "SkipReason should match policy value")

	// skip_reason empty string should be decoded, and is treated as not set by Status
	regoContentsEmptySkip := []byte(`package compliance_framework.empty_skip_test

import future.keywords.in

title := "This should not be skipped"
description := "This evidence should be produced"
skip_reason := ""

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	results, err = buildEvaluator(regoContentsEmptySkip).Execute(ctx, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0].SkipReason, "SkipReason field should be set even when empty")
	assert.Equal(t, "", *results[0].SkipReason, "SkipReason should be empty string")

	// skip_reason not set should be nil
	regoContentsNoSkipField := []byte(`package compliance_framework.no_skip_field

import future.keywords.in

title := "This should not be skipped"
description := "This evidence should be produced"

violation[{
    "title": "Test violation",
}] if {
	false
}
`)

	results, err = buildEvaluator(regoContentsNoSkipField).Execute(ctx, map[string]interface{}{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Nil(t, results[0].SkipReason, "SkipReason field should be nil when not set")
}
