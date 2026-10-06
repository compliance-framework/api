package agentconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	t.Run("defaults with auth", func(t *testing.T) {
		got := RemoteConfig{}.Normalize(true)
		assert.Equal(t, RemoteConfig{
			Mode:                   ModeReport,
			PollInterval:           "60s",
			TrustedSources:         []string{},
			OverridableConfigFlags: []string{},
			AllowLocalSources:      false,
		}, got)
		require.NotNil(t, got.TrustedSources, "[] not nil")
		require.NotNil(t, got.OverridableConfigFlags, "[] not nil")
	})
	t.Run("unset mode with auth reports, never applies", func(t *testing.T) {
		rc := RemoteConfig{PollInterval: "2m"}.Normalize(true)
		assert.Equal(t, ModeReport, rc.Mode)
		apply, reason := WillApply(rc, nil)
		assert.False(t, apply, "an agent that did not opt in never applies")
		assert.Equal(t, WillApplyReasonModeReport, reason)
	})
	t.Run("explicit modes kept with auth", func(t *testing.T) {
		for _, mode := range []string{ModeOff, ModeReport, ModeApplySafe, ModeApplyAll} {
			assert.Equal(t, mode, RemoteConfig{Mode: mode}.Normalize(true).Mode, mode)
		}
	})
	t.Run("no auth forces off", func(t *testing.T) {
		for _, mode := range []string{"", ModeOff, ModeReport, ModeApplySafe, ModeApplyAll} {
			assert.Equal(t, ModeOff, RemoteConfig{Mode: mode}.Normalize(false).Mode, mode)
		}
	})
	t.Run("explicit values kept", func(t *testing.T) {
		in := RemoteConfig{
			Mode:                   ModeReport,
			PollInterval:           "5m",
			TrustedSources:         []string{"ghcr.io/*"},
			OverridableConfigFlags: []string{"*"},
			AllowLocalSources:      true,
		}
		got := in.Normalize(true)
		assert.Equal(t, ModeReport, got.Mode)
		assert.Equal(t, "5m", got.PollInterval)
		assert.Equal(t, []string{"ghcr.io/*"}, got.TrustedSources)
		assert.Equal(t, []string{"*"}, got.OverridableConfigFlags)
		assert.True(t, got.AllowLocalSources)

		// The result does not alias the input.
		got.TrustedSources[0] = "changed"
		assert.Equal(t, "ghcr.io/*", in.TrustedSources[0])
	})
	t.Run("empty slices stay empty", func(t *testing.T) {
		got := RemoteConfig{TrustedSources: []string{}, OverridableConfigFlags: []string{}}.Normalize(true)
		assert.Equal(t, []string{}, got.TrustedSources)
		assert.Equal(t, []string{}, got.OverridableConfigFlags)
	})
	t.Run("idempotent", func(t *testing.T) {
		once := RemoteConfig{Mode: ModeApplyAll}.Normalize(true)
		assert.Equal(t, once, once.Normalize(true))
	})
}

func TestEffectiveRemoteConfig(t *testing.T) {
	withAuth := &APIConfig{URL: "http://x", Auth: &APIAuth{ClientID: "id", ClientSecret: "secret"}}

	assert.Equal(t, ModeReport, Config{API: withAuth}.EffectiveRemoteConfig().Mode, "unset mode defaults to report")
	assert.Equal(t, ModeApplySafe, Config{API: withAuth, RemoteConfig: &RemoteConfig{Mode: ModeApplySafe}}.EffectiveRemoteConfig().Mode)
	assert.Equal(t, ModeOff, Config{}.EffectiveRemoteConfig().Mode, "nil api")
	assert.Equal(t, ModeOff, Config{API: &APIConfig{URL: "http://x"}}.EffectiveRemoteConfig().Mode, "no auth")
	assert.Equal(t, ModeOff, Config{API: &APIConfig{URL: "http://x", Auth: &APIAuth{ClientID: "id", ClientSecret: " "}}}.EffectiveRemoteConfig().Mode, "blank secret")
	assert.Equal(t, ModeOff, Config{API: &APIConfig{URL: "http://x"}, RemoteConfig: &RemoteConfig{Mode: ModeApplyAll}}.EffectiveRemoteConfig().Mode)
	got := Config{API: withAuth, RemoteConfig: &RemoteConfig{Mode: ModeReport, PollInterval: "2m"}}.EffectiveRemoteConfig()
	assert.Equal(t, ModeReport, got.Mode)
	assert.Equal(t, "2m", got.PollInterval)
}

func TestAPIConfigAuth(t *testing.T) {
	tests := []struct {
		name        string
		api         *APIConfig
		has, partia bool
	}{
		{name: "nil", api: nil},
		{name: "no auth", api: &APIConfig{}},
		{name: "empty auth", api: &APIConfig{Auth: &APIAuth{}}},
		{name: "both", api: &APIConfig{Auth: &APIAuth{ClientID: "a", ClientSecret: "b"}}, has: true},
		{name: "id only", api: &APIConfig{Auth: &APIAuth{ClientID: "a"}}, partia: true},
		{name: "secret only", api: &APIConfig{Auth: &APIAuth{ClientSecret: "b"}}, partia: true},
		{name: "blank secret", api: &APIConfig{Auth: &APIAuth{ClientID: "a", ClientSecret: "  "}}, partia: true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.has, tt.api.HasAuth(), tt.name)
		assert.Equal(t, tt.partia, tt.api.HasPartialAuth(), tt.name)
	}
}

func TestPluginIsEnabled(t *testing.T) {
	assert.False(t, (*Plugin)(nil).IsEnabled())
	assert.True(t, (&Plugin{}).IsEnabled())
	assert.True(t, (&Plugin{Enabled: boolPtr(true)}).IsEnabled())
	assert.False(t, (&Plugin{Enabled: boolPtr(false)}).IsEnabled())
}

// trustedSourcePatterns, trustedSourceCases and trustedSourceExtraCases are the
// MatchTrustedSource table, shared with the conformance golden file (conformance_test.go).
var trustedSourcePatterns = []string{"ghcr.io/compliance-framework/*", "docker.io/acme/plugin-?:v1", "[bad"}

var trustedSourceCases = []struct {
	source string
	want   bool
}{
	{"ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0", true},
	{"ghcr.io/compliance-framework/sub/plugin:v1", false}, // '*' does not cross '/'
	{"ghcr.io/Compliance-Framework/plugin:v1", false},     // case-sensitive
	{"ghcr.io/compliance-framework", false},
	{"ghcr.io/other/plugin:v1", false},
	{"docker.io/acme/plugin-a:v1", true},
	{"docker.io/acme/plugin-ab:v1", false},
	{"", false},
}

var trustedSourceExtraCases = []struct {
	patterns []string
	source   string
	want     bool
}{
	{patterns: nil, source: "ghcr.io/x/y:v1", want: false}, // default [] trusts nothing
	{patterns: []string{"*/*/*"}, source: "ghcr.io/x/y:v1", want: true},
}

func TestMatchTrustedSource(t *testing.T) {
	rc := RemoteConfig{TrustedSources: trustedSourcePatterns}
	for _, tt := range trustedSourceCases {
		assert.Equal(t, tt.want, MatchTrustedSource(rc, tt.source), tt.source)
	}
	for _, tt := range trustedSourceExtraCases {
		assert.Equal(t, tt.want, MatchTrustedSource(RemoteConfig{TrustedSources: tt.patterns}, tt.source), "%v %s", tt.patterns, tt.source)
	}
}

// overridableConfigFlagCases is the MatchOverridableConfigFlag table, shared with the
// conformance golden file (conformance_test.go).
var overridableConfigFlagCases = []struct {
	name   string
	flags  []string
	plugin string
	key    string
	want   bool
}{
	{name: "default empty", flags: nil, plugin: "local-ssh", key: "port", want: false},
	{name: "star", flags: []string{"*"}, plugin: "local-ssh", key: "port", want: true},
	{name: "star any plugin", flags: []string{"*"}, plugin: "other", key: "anything", want: true},
	{name: "scoped match", flags: []string{"local-ssh:port"}, plugin: "local-ssh", key: "port", want: true},
	{name: "scoped other key", flags: []string{"local-ssh:port"}, plugin: "local-ssh", key: "host", want: false},
	{name: "scoped other plugin", flags: []string{"local-ssh:port"}, plugin: "remote-ssh", key: "port", want: false},
	{name: "unscoped key any plugin", flags: []string{"port"}, plugin: "remote-ssh", key: "port", want: true},
	{name: "plugin glob", flags: []string{"*-ssh:port"}, plugin: "remote-ssh", key: "port", want: true},
	{name: "key glob", flags: []string{"local-ssh:tls_*"}, plugin: "local-ssh", key: "tls_verify", want: true},
	{name: "case-sensitive", flags: []string{"local-ssh:Port"}, plugin: "local-ssh", key: "port", want: false},
	{name: "split at first colon", flags: []string{"p*:a:b"}, plugin: "p1", key: "a:b", want: true},
	{name: "split at first colon, plugin side", flags: []string{"p*:a:b"}, plugin: "p1:a", key: "b", want: false},
	{name: "bad glob skipped", flags: []string{"[x:port", "local-ssh:[", "local-ssh:port"}, plugin: "local-ssh", key: "port", want: true},
	{name: "only bad globs", flags: []string{"[x:port", "local-ssh:["}, plugin: "local-ssh", key: "port", want: false},
}

func TestMatchOverridableConfigFlag(t *testing.T) {
	for _, tt := range overridableConfigFlagCases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchOverridableConfigFlag(RemoteConfig{OverridableConfigFlags: tt.flags}, tt.plugin, tt.key))
		})
	}
}
