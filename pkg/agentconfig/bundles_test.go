package agentconfig

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateModulePath(t *testing.T) {
	valid := []string{
		"a.rego",
		"banner.rego",
		"sub/dir/x_test.rego",
		"A-b_c.rego",
		"data.json",
		"data.yaml",
		"data.yml",
		"sub/data.yml",
		"deep/er/data.json",
		"a.b.rego",
	}
	for _, p := range valid {
		assert.NoError(t, ValidateModulePath(p), p)
	}
	invalid := []string{
		"",
		"../x.rego",
		"/abs.rego",
		"a/../../b.rego",
		"a//b.rego",
		"./a.rego",
		"a/./b.rego",
		"sub/",
		"a.rego/",
		"foo.json",
		"foo.yaml",
		"sub/config.yml",
		"data.json.bak",
		"a.txt",
		"a",
		"a b.rego",
		"ä.rego",
		`a\b.rego`,
		".rego",
	}
	for _, p := range invalid {
		assert.Error(t, ValidateModulePath(p), p)
	}
}

func TestValidateBundlesValid(t *testing.T) {
	bundles := map[string]*PolicyBundle{
		"standalone": {Modules: map[string]string{"a.rego": "package a", "sub/data.yml": "a: 1\nb: [1, 2]\n", "x/data.json": `{"a":1}`}},
		"extends":    {Extends: strPtr(srcPolicies), Delete: []string{"old.rego", "sub/data.yaml"}},
		"data-only":  {Data: map[string]any{"a": 1}},
		"empty-data": {Data: map[string]any{}},
		"nested-data-file-with-data": {
			Data:    map[string]any{"a": 1},
			Modules: map[string]string{"sub/data.json": "{}"},
		},
	}
	assert.Empty(t, ValidateBundles(bundles))
	assert.Empty(t, ValidateBundles(nil))
}

func TestValidateBundles(t *testing.T) {
	big := strings.Repeat("x", MaxModuleBytes)
	tests := []struct {
		name     string
		bundles  map[string]*PolicyBundle
		bundle   string
		path     string
		contains string
	}{
		{name: "invalid name", bundles: map[string]*PolicyBundle{"Ssh.Tuned": {Modules: map[string]string{"a.rego": "package a"}}}, bundle: "Ssh.Tuned", contains: "must match"},
		{name: "empty name", bundles: map[string]*PolicyBundle{"": {Modules: map[string]string{"a.rego": "package a"}}}, bundle: "", contains: "must match"},
		{name: "nil bundle", bundles: map[string]*PolicyBundle{"b": nil}, bundle: "b", contains: "no definition"},
		{name: "empty bundle", bundles: map[string]*PolicyBundle{"b": {}}, bundle: "b", contains: "at least one"},
		{name: "empty modules only", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{}}}, bundle: "b", contains: "at least one"},
		{name: "extends inline", bundles: map[string]*PolicyBundle{"b": {Extends: strPtr("inline:x")}}, bundle: "b", contains: "not an inline bundle"},
		{name: "extends empty", bundles: map[string]*PolicyBundle{"b": {Extends: strPtr(" ")}}, bundle: "b", contains: "must not be empty"},
		{name: "traversal ../x.rego", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"../x.rego": "package x"}}}, bundle: "b", path: "../x.rego"},
		{name: "traversal /abs.rego", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"/abs.rego": "package x"}}}, bundle: "b", path: "/abs.rego"},
		{name: "traversal a/../../b.rego", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"a/../../b.rego": "package x"}}}, bundle: "b", path: "a/../../b.rego"},
		{name: "traversal a//b.rego", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"a//b.rego": "package x"}}}, bundle: "b", path: "a//b.rego"},
		{name: "traversal ./a.rego", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"./a.rego": "package x"}}}, bundle: "b", path: "./a.rego"},
		{name: "foo.json", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"foo.json": "{}"}}}, bundle: "b", path: "foo.json", contains: "data.json"},
		{name: "data and data.json", bundles: map[string]*PolicyBundle{"b": {Data: map[string]any{"a": 1}, Modules: map[string]string{"data.json": "{}"}}}, bundle: "b", path: "data.json", contains: "either data"},
		{name: "data and data.yaml", bundles: map[string]*PolicyBundle{"b": {Data: map[string]any{}, Modules: map[string]string{"data.yaml": "a: 1"}}}, bundle: "b", path: "data.yaml", contains: "either data"},
		{name: "module too big", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"a.rego": big + "x"}}}, bundle: "b", path: "a.rego", contains: "limit"},
		{name: "bad data.json", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"data.json": "{"}}}, bundle: "b", path: "data.json", contains: "does not parse"},
		{name: "bad data.yaml", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"data.yaml": "a: [1"}}}, bundle: "b", path: "data.yaml", contains: "does not parse"},
		{name: "bad nested data.yml", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"sub/data.yml": "a:\n\t- b"}}}, bundle: "b", path: "sub/data.yml", contains: "does not parse"},
		{name: "delete without extends", bundles: map[string]*PolicyBundle{"b": {Modules: map[string]string{"a.rego": "package a"}, Delete: []string{"x.rego"}}}, bundle: "b", contains: "requires extends"},
		{name: "delete also in modules", bundles: map[string]*PolicyBundle{"b": {Extends: strPtr(srcPolicies), Modules: map[string]string{"a.rego": "package a"}, Delete: []string{"a.rego"}}}, bundle: "b", path: "a.rego", contains: "both deleted"},
		{name: "delete bad path", bundles: map[string]*PolicyBundle{"b": {Extends: strPtr(srcPolicies), Delete: []string{"../x.rego"}}}, bundle: "b", path: "../x.rego"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := ValidateBundles(tt.bundles)
			require.NotEmpty(t, errs)
			assert.True(t, HasPolicyErrors(errs))
			var found bool
			for _, e := range errs {
				assert.Equal(t, SeverityError, e.Severity)
				if e.Bundle == tt.bundle && e.Path == tt.path && strings.Contains(e.Message, tt.contains) {
					found = true
				}
			}
			assert.True(t, found, "no error for bundle %q path %q containing %q in %#v", tt.bundle, tt.path, tt.contains, errs)
		})
	}
}

func TestValidateBundlesSizes(t *testing.T) {
	exact := strings.Repeat("x", MaxModuleBytes)
	assert.Empty(t, ValidateBundles(map[string]*PolicyBundle{"b": {Modules: map[string]string{"a.rego": exact}}}), "MaxModuleBytes is allowed")

	errs := ValidateBundles(map[string]*PolicyBundle{"b": {Modules: map[string]string{"a.rego": exact + "x"}}})
	require.Len(t, errs, 1)
	assert.Equal(t, "a.rego", errs[0].Path)

	// Four maximal modules are exactly MaxBundleBytes.
	four := map[string]string{"a.rego": exact, "b.rego": exact, "c.rego": exact, "d.rego": exact}
	require.Equal(t, MaxBundleBytes, 4*MaxModuleBytes)
	assert.Empty(t, ValidateBundles(map[string]*PolicyBundle{"b": {Modules: four}}), "MaxBundleBytes is allowed")

	// One more byte of data tips the bundle over.
	errs = ValidateBundles(map[string]*PolicyBundle{"b": {Modules: four, Data: map[string]any{}}})
	require.Len(t, errs, 1, "len(json({})) = 2 bytes over: %#v", errs)
	assert.Equal(t, "", errs[0].Path)
	assert.Contains(t, errs[0].Message, "bundle is")

	five := map[string]string{"a.rego": exact, "b.rego": exact, "c.rego": exact, "d.rego": exact, "e.rego": "x"}
	errs = ValidateBundles(map[string]*PolicyBundle{"b": {Modules: five}})
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Message, "bundle is")
}

func TestValidateBundlesSorted(t *testing.T) {
	errs := ValidateBundles(map[string]*PolicyBundle{
		"z": {},
		"a": {Modules: map[string]string{"z.json": "{}", "b.json": "{}"}},
	})
	var got []string
	for _, e := range errs {
		got = append(got, e.Bundle+":"+e.Path)
	}
	assert.Equal(t, []string{"a:b.json", "a:z.json", "z:"}, got)
}

func TestValidateBundlesFieldErrorPaths(t *testing.T) {
	c := Config{
		API: &APIConfig{URL: "http://x"},
		PolicyBundles: map[string]*PolicyBundle{
			"b": {
				Modules: map[string]string{"sub/foo.json": "{}"},
				Delete:  []string{"a.rego"},
				Data:    map[string]any{"a": 1},
			},
		},
	}
	err := c.ValidateEditable()
	requireFieldError(t, err, "/policy_bundles/b/modules/sub~1foo.json", FieldCodePattern)
	requireFieldError(t, err, "/policy_bundles/b/delete", FieldCodeConflict)
}

func TestHasPolicyErrors(t *testing.T) {
	assert.False(t, HasPolicyErrors(nil))
	assert.False(t, HasPolicyErrors([]PolicyError{{Severity: SeverityWarning}}))
	assert.True(t, HasPolicyErrors([]PolicyError{{Severity: SeverityWarning}, {Severity: SeverityError}}))
}

func TestSortPolicyErrors(t *testing.T) {
	errs := []PolicyError{
		{Bundle: "b", Path: "a.rego", Row: 2, Col: 1, Message: "x"},
		{Bundle: "a", Path: "z.rego", Row: 1, Col: 1, Message: "x"},
		{Bundle: "b", Path: "a.rego", Row: 1, Col: 5, Message: "x"},
		{Bundle: "b", Path: "a.rego", Row: 1, Col: 2, Message: "y"},
		{Bundle: "b", Path: "a.rego", Row: 1, Col: 2, Message: "a"},
		{Bundle: "b", Path: "", Message: "bundle"},
	}
	SortPolicyErrors(errs)
	assert.Equal(t, []PolicyError{
		{Bundle: "a", Path: "z.rego", Row: 1, Col: 1, Message: "x"},
		{Bundle: "b", Path: "", Message: "bundle"},
		{Bundle: "b", Path: "a.rego", Row: 1, Col: 2, Message: "a"},
		{Bundle: "b", Path: "a.rego", Row: 1, Col: 2, Message: "y"},
		{Bundle: "b", Path: "a.rego", Row: 1, Col: 5, Message: "x"},
		{Bundle: "b", Path: "a.rego", Row: 2, Col: 1, Message: "x"},
	}, errs)
}
