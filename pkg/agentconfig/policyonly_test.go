package agentconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	vendorS = "ghcr.io/compliance-framework/plugin-local-ssh-policies:v1.0.0"
	vendorT = "ghcr.io/compliance-framework/common-policies:v1"
)

// policyBase is a reported base with plugin p running two vendor policy sets.
func policyBase() Config {
	return Config{
		Plugins: map[string]*Plugin{
			"p": {Source: srcSSH, Schedule: strPtr("*/5 * * * *"), Policies: []string{vendorS, vendorT}},
			"q": {Source: srcSSH, Policies: []string{vendorS}},
		},
	}
}

func TestPolicyOnlyChange(t *testing.T) {
	bundleB := `"policy_bundles":{"b":{"extends":"` + vendorS + `","modules":{"x.rego":"package x"}}}`
	bundleBOther := `"policy_bundles":{"b":{"extends":"` + srcUntrusted + `","modules":{"x.rego":"package x"}}}`
	bundleX := `"policy_bundles":{"x":{"modules":{"x.rego":"package x"}}}`

	tests := []struct {
		name          string
		current, next string
		bases         []Config
		want          bool
	}{
		{name: "identical", current: `{"verbosity":1}`, next: `{"verbosity":1}`, bases: []Config{policyBase()}, want: true},
		{name: "empty to empty", current: ``, next: `{}`, bases: []Config{policyBase()}, want: true},
		{
			name:    "module edit",
			current: `{"policy_bundles":{"x":{"modules":{"x.rego":"package x"}}}}`,
			next:    `{"policy_bundles":{"x":{"modules":{"x.rego":"package x\nallow := true"}}}}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{name: "bundle added", current: `{}`, next: `{` + bundleX + `}`, bases: []Config{policyBase()}, want: true},
		{name: "bundle removed", current: `{` + bundleX + `}`, next: `{"policy_bundles":{"x":null}}`, bases: []Config{policyBase()}, want: true},
		{
			name:    "first-time policies: add inline keeping vendors",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `","inline:x"]}},` + bundleX + `}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "add inline in the middle keeping vendor order",
			current: `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `"]}}}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","inline:x","` + vendorT + `"]}}}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "remove inline",
			current: `{"plugins":{"p":{"policies":["` + vendorS + `","inline:x","` + vendorT + `"]}}}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `"]}}}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "remove the policies key again (back to the file list)",
			current: `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `","inline:x"]}}}`,
			next:    `{}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "inline replacing the file list",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["inline:x"]}},` + bundleX + `}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "reorder vendors",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorT + `","` + vendorS + `"]}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "add vendor source",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `","` + srcUntrusted + `"]}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "swap S to inline:B with B.extends == S",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["inline:b","` + vendorT + `"]}},` + bundleB + `}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "swap inline:B back to S",
			current: `{"plugins":{"p":{"policies":["inline:b","` + vendorT + `"]}},` + bundleB + `}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `"]}},"policy_bundles":{"b":null}}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "swap inline:B back to S keeping the bundle",
			current: `{"plugins":{"p":{"policies":["inline:b","` + vendorT + `"]}},` + bundleB + `}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `"]}},` + bundleB + `}`,
			bases:   []Config{policyBase()},
			want:    true,
		},
		{
			name:    "swap with B.extends != S",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["inline:b","` + vendorT + `"]}},` + bundleBOther + `}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "swap with an unknown bundle",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["inline:nope","` + vendorT + `"]}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "swap plus an extra inline add",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["inline:b","` + vendorT + `","inline:x"]}},` + bundleB + `}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "swap plus removal of another vendor",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["inline:b"]}},` + bundleB + `}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "schedule change",
			current: `{}`,
			next:    `{"plugins":{"p":{"schedule":"@hourly"}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "policies plus config change",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `","inline:x"],"config":{"a":"b"}}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{name: "verbosity change", current: `{}`, next: `{"verbosity":2}`, bases: []Config{policyBase()}, want: false},
		{name: "plugin removed", current: `{}`, next: `{"plugins":{"p":null}}`, bases: []Config{policyBase()}, want: false},
		{
			name:    "new plugin via policies",
			current: `{}`,
			next:    `{"plugins":{"new":{"policies":["inline:x"]}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
		{
			name:    "no bases is conservative: plugin unknown",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":["` + vendorS + `","` + vendorT + `","inline:x"]}}}`,
			bases:   nil,
			want:    false,
		},
		{
			name:    "no bases: bundle-only change is fine",
			current: `{}`,
			next:    `{` + bundleX + `}`,
			bases:   nil,
			want:    true,
		},
		{
			name:    "no bases: plugin defined by the overlay itself",
			current: `{"plugins":{"p":{"source":"` + srcSSH + `","policies":["` + vendorS + `"]}}}`,
			next:    `{"plugins":{"p":{"source":"` + srcSSH + `","policies":["` + vendorS + `","inline:x"]}}}`,
			bases:   nil,
			want:    true,
		},
		{
			name:    "every base must allow it",
			current: `{}`,
			next:    `{"plugins":{"q":{"policies":["` + vendorS + `","inline:x"]}}}`,
			bases: []Config{policyBase(), {Plugins: map[string]*Plugin{
				"q": {Source: srcSSH, Policies: []string{vendorT}},
			}}},
			want: false,
		},
		{
			name:    "every base allows it",
			current: `{}`,
			next:    `{"plugins":{"q":{"policies":["` + vendorS + `","inline:x"]}}}`,
			bases: []Config{policyBase(), {Plugins: map[string]*Plugin{
				"q": {Source: srcSSH, Policies: []string{vendorS}, Schedule: strPtr("@hourly")},
			}}},
			want: true,
		},
		{
			name:    "plugin missing in one base",
			current: `{}`,
			next:    `{"plugins":{"q":{"policies":["` + vendorS + `","inline:x"]}}}`,
			bases:   []Config{policyBase(), {}},
			want:    false,
		},
		{name: "new empty plugin object", current: `{}`, next: `{"plugins":{"new":{}}}`, bases: []Config{policyBase()}, want: false},
		{name: "new empty plugin object, no bases", current: `{}`, next: `{"plugins":{"new":{}}}`, bases: nil, want: false},
		{name: "empty object for an existing plugin is no change", current: `{}`, next: `{"plugins":{"p":{}}}`, bases: []Config{policyBase()}, want: true},
		{name: "empty plugins object is no change", current: `{}`, next: `{"plugins":{}}`, bases: []Config{policyBase()}, want: true},
		{name: "invalid current", current: `{`, next: `{}`, bases: []Config{policyBase()}, want: false},
		{name: "invalid next", current: `{}`, next: `nope`, bases: []Config{policyBase()}, want: false},
		{
			name:    "merge failure",
			current: `{}`,
			next:    `{"plugins":{"p":{"policies":[1]}}}`,
			bases:   []Config{policyBase()},
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, PolicyOnlyChange(json.RawMessage(tt.current), json.RawMessage(tt.next), tt.bases))
		})
	}
}
