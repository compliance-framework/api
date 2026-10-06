package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// sourceKindCases, pluginNamesValid and pluginNamesInvalid are shared with the conformance
// golden file (conformance_test.go).
var sourceKindCases = []struct {
	source string
	kind   SourceKind
}{
	{"ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0", SourceKindOCI},
	{"ghcr.io/compliance-framework/plugin-local-ssh-policies:latest", SourceKindOCI},
	{"docker.io/library/alpine:3.20", SourceKindOCI},
	{"localhost:5000/plugin:v1", SourceKindOCI},
	{"registry.example.com:5000/a/b/c:1.2.3", SourceKindOCI},
	{"ghcr.io/x/y", SourceKindLocal}, // strict validation requires an explicit tag
	{"ghcr.io/X/Y:v1", SourceKindLocal},
	{"ghcr.io/x/y:", SourceKindLocal},
	{"./plugins/foo", SourceKindLocal},
	{"/opt/plugin", SourceKindLocal},
	{"plugin", SourceKindLocal},
	{"", SourceKindLocal},
	{"inline:ssh", SourceKindLocal},                // no special meaning: a local path
	{"foo%.com/acme/plugin:v1", SourceKindLocal},   // a '%' registry does not parse back unchanged
	{"foo%41.com/acme/plugin:v1", SourceKindLocal}, // nor does a percent-escape
}

var (
	pluginNamesValid   = []string{"a", "0", "local-ssh", "ssh_tuned", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk"}
	pluginNamesInvalid = []string{"", "GitHub", "Ssh.Tuned", "-a", "_a", "a.b", "a b", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl"}
)

func TestKindOfAndIsOCISource(t *testing.T) {
	for _, tt := range sourceKindCases {
		t.Run(tt.source, func(t *testing.T) {
			assert.Equal(t, tt.kind, KindOf(tt.source))
			assert.Equal(t, tt.kind == SourceKindOCI, IsOCISource(tt.source))
		})
	}
}

func TestNamePatterns(t *testing.T) {
	for _, ok := range pluginNamesValid {
		assert.True(t, PluginNamePattern.MatchString(ok), ok)
	}
	for _, bad := range pluginNamesInvalid {
		assert.False(t, PluginNamePattern.MatchString(bad), bad)
	}
}
