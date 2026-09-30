package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKindOfAndIsOCISource(t *testing.T) {
	tests := []struct {
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
		{"inline:ssh", SourceKindInline},
		{"inline:", SourceKindInline},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			assert.Equal(t, tt.kind, KindOf(tt.source))
			assert.Equal(t, tt.kind == SourceKindOCI, IsOCISource(tt.source))
			assert.Equal(t, tt.kind == SourceKindInline, IsInlineSource(tt.source))
		})
	}
}

func TestInlineBundleName(t *testing.T) {
	tests := []struct {
		in     string
		name   string
		wantOK bool
	}{
		{"inline:ssh", "ssh", true},
		{"inline:Ssh.Tuned", "Ssh.Tuned", true}, // not pattern-checked
		{"inline:", "", false},
		{"ssh", "", false},
		{"Inline:ssh", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		name, ok := InlineBundleName(tt.in)
		assert.Equal(t, tt.wantOK, ok, tt.in)
		assert.Equal(t, tt.name, name, tt.in)
	}
}

func TestNamePatterns(t *testing.T) {
	for _, ok := range []string{"a", "0", "local-ssh", "ssh_tuned", "a" + string(make([]byte, 0)), "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk"} {
		assert.True(t, PluginNamePattern.MatchString(ok), ok)
	}
	for _, bad := range []string{"", "GitHub", "Ssh.Tuned", "-a", "_a", "a.b", "a b", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl"} {
		assert.False(t, PluginNamePattern.MatchString(bad), bad)
	}
	assert.Same(t, PluginNamePattern, BundleNamePattern)
}
