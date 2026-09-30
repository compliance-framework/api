package agentconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMergePatchRFC7396AppendixA runs every example of RFC 7396 Appendix A.
func TestMergePatchRFC7396AppendixA(t *testing.T) {
	tests := []struct {
		target, patch, want string
	}{
		{`{"a":"b"}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"b"}`, `{"b":"c"}`, `{"a":"b","b":"c"}`},
		{`{"a":"b"}`, `{"a":null}`, `{}`},
		{`{"a":"b","b":"c"}`, `{"a":null}`, `{"b":"c"}`},
		{`{"a":["b"]}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"c"}`, `{"a":["b"]}`, `{"a":["b"]}`},
		{`{"a":{"b":"c"}}`, `{"a":{"b":"d","c":null}}`, `{"a":{"b":"d"}}`},
		{`{"a":[{"b":"c"}]}`, `{"a":[1]}`, `{"a":[1]}`},
		{`["a","b"]`, `["c","d"]`, `["c","d"]`},
		{`{"a":"b"}`, `["c"]`, `["c"]`},
		{`{"a":"foo"}`, `null`, `null`},
		{`{"a":"foo"}`, `"bar"`, `"bar"`},
		{`{"e":null}`, `{"a":1}`, `{"a":1,"e":null}`},
		{`[1,2]`, `{"a":"b","c":null}`, `{"a":"b"}`},
		{`{}`, `{"a":{"bb":{"ccc":null}}}`, `{"a":{"bb":{}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.target+"+"+tt.patch, func(t *testing.T) {
			got, err := MergePatch([]byte(tt.target), []byte(tt.patch))
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestMergePatch(t *testing.T) {
	tests := []struct {
		name          string
		target, patch string
		want          string
		wantExact     bool // compare bytes, not JSONEq
	}{
		{name: "nil target is null", target: "", patch: `{"a":1}`, want: `{"a":1}`},
		{name: "null target", target: "null", patch: `{"a":{"b":null,"c":2}}`, want: `{"a":{"c":2}}`},
		{name: "nested null delete", target: `{"a":{"b":{"c":1,"d":2},"e":3}}`, patch: `{"a":{"b":{"c":null}}}`, want: `{"a":{"b":{"d":2},"e":3}}`},
		{name: "deep null delete of object", target: `{"a":{"b":{"c":1}},"x":1}`, patch: `{"a":{"b":null}}`, want: `{"a":{},"x":1}`},
		{name: "arrays replaced wholesale", target: `{"p":["a","b","c"]}`, patch: `{"p":["z"]}`, want: `{"p":["z"]}`},
		{name: "array replaced by empty array", target: `{"p":["a"]}`, patch: `{"p":[]}`, want: `{"p":[]}`},
		{name: "object replaces scalar", target: `{"a":1}`, patch: `{"a":{"b":1}}`, want: `{"a":{"b":1}}`},
		{name: "large integers preserved", target: `{"n":12345678901234567890,"f":1.10}`, patch: `{"m":9007199254740993}`, want: `{"f":1.10,"m":9007199254740993,"n":12345678901234567890}`, wantExact: true},
		{name: "output is canonical: sorted, no HTML escaping", target: `{"b":"<x>","a":"&"}`, patch: `{}`, want: `{"a":"&","b":"<x>"}`, wantExact: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MergePatch([]byte(tt.target), []byte(tt.patch))
			require.NoError(t, err)
			if tt.wantExact {
				assert.Equal(t, tt.want, string(got))
			} else {
				assert.JSONEq(t, tt.want, string(got))
			}
		})
	}
}

func TestMergePatchErrors(t *testing.T) {
	_, err := MergePatch([]byte(`{`), []byte(`{}`))
	assert.Error(t, err)
	_, err = MergePatch([]byte(`{}`), []byte(`{"a":`))
	assert.Error(t, err)
	_, err = MergePatch([]byte(`{}`), []byte(`{} {}`))
	assert.Error(t, err, "trailing data")
}

func TestStripLocked(t *testing.T) {
	tests := []struct {
		name        string
		overlay     string
		want        string
		wantRemoved []string
		wantErr     bool
	}{
		{name: "nil", overlay: "", want: `{}`},
		{name: "whitespace", overlay: "  \n", want: `{}`},
		{name: "null", overlay: "null", want: `{}`},
		{name: "empty object", overlay: `{}`, want: `{}`},
		{name: "no locked keys", overlay: `{"verbosity":1,"plugins":{"x":{"source":"s"}}}`, want: `{"plugins":{"x":{"source":"s"}},"verbosity":1}`},
		{name: "api only", overlay: `{"api":{"url":"http://evil"},"verbosity":2}`, want: `{"verbosity":2}`, wantRemoved: []string{"api"}},
		{
			name:        "all locked keys, including null values",
			overlay:     `{"remote_config":null,"daemon":true,"api":null,"plugins":{}}`,
			want:        `{"plugins":{}}`,
			wantRemoved: []string{"api", "daemon", "remote_config"},
		},
		{name: "nested keys named like locked keys are kept", overlay: `{"plugins":{"api":{"config":{"daemon":"1"}}}}`, want: `{"plugins":{"api":{"config":{"daemon":"1"}}}}`},
		{name: "array overlay", overlay: `[1]`, wantErr: true},
		{name: "string overlay", overlay: `"x"`, wantErr: true},
		{name: "invalid json", overlay: `{"a"`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, removed, err := StripLocked([]byte(tt.overlay))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
			assert.Equal(t, tt.wantRemoved, removed)
		})
	}
}

func lockedBase() Config {
	return Config{
		Daemon:    true,
		Verbosity: 1,
		API: &APIConfig{
			URL:  "https://api.example.com",
			Auth: &APIAuth{ClientID: "0b3c1b8a-7c8e-4d53-9a52-9a3c1d1f2e10", ClientSecret: "s3cret"},
		},
		RemoteConfig: &RemoteConfig{
			Mode:                   ModeApplySafe,
			PollInterval:           "30s",
			TrustedSources:         []string{"ghcr.io/compliance-framework/*"},
			OverridableConfigFlags: []string{"local-ssh:port"},
			AllowInlinePolicies:    boolPtr(false),
		},
		Plugins: map[string]*Plugin{
			"local-ssh": {
				Source:   "ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0",
				Schedule: strPtr("*/5 * * * *"),
				Policies: []string{"ghcr.io/compliance-framework/plugin-local-ssh-policies:v1.0.0"},
				Config:   map[string]string{"host": "localhost", "port": "22"},
			},
		},
	}
}

func TestMergeLockedKeysAlwaysFromBase(t *testing.T) {
	overlays := []string{
		`{"api":{"url":"https://evil.example.com","auth":{"client_id":"x","client_secret":"y"}}}`,
		`{"api":null}`,
		`{"daemon":false}`,
		`{"daemon":null}`,
		`{"remote_config":{"mode":"apply_all","allow_local_sources":true,"trusted_sources":["*"]}}`,
		`{"remote_config":null}`,
		`{"api":null,"daemon":false,"remote_config":null,"verbosity":2}`,
	}
	for _, o := range overlays {
		t.Run(o, func(t *testing.T) {
			base := lockedBase()
			eff, err := Merge(base, json.RawMessage(o))
			require.NoError(t, err)
			assert.Equal(t, base.API, eff.API)
			assert.Equal(t, base.Daemon, eff.Daemon)
			assert.Equal(t, base.RemoteConfig, eff.RemoteConfig)
			assert.Equal(t, lockedBase(), base, "base must not be mutated")
		})
	}
}

func TestMerge(t *testing.T) {
	t.Run("empty and null overlays keep base", func(t *testing.T) {
		for _, o := range []string{"", "null", "{}"} {
			base := lockedBase()
			eff, err := Merge(base, json.RawMessage(o))
			require.NoError(t, err, o)
			assert.Equal(t, base, eff, o)
		}
	})

	t.Run("overlay changes plugin fields and adds a plugin", func(t *testing.T) {
		eff, err := Merge(lockedBase(), json.RawMessage(`{
			"verbosity": 2,
			"plugins": {
				"local-ssh": {"config": {"port": "2222", "host": null}, "schedule": null, "labels": {"env": "prod"}},
				"new": {"source": "ghcr.io/x/y:v1"}
			}
		}`))
		require.NoError(t, err)
		assert.Equal(t, int32(2), eff.Verbosity)
		ssh := eff.Plugins["local-ssh"]
		require.NotNil(t, ssh)
		assert.Equal(t, map[string]string{"port": "2222"}, ssh.Config)
		assert.Nil(t, ssh.Schedule, "schedule: null deletes the key")
		assert.Equal(t, map[string]string{"env": "prod"}, ssh.Labels)
		assert.Equal(t, lockedBase().Plugins["local-ssh"].Policies, ssh.Policies)
		require.NotNil(t, eff.Plugins["new"])
		assert.Equal(t, "ghcr.io/x/y:v1", eff.Plugins["new"].Source)
	})

	t.Run("plugin null deletes it", func(t *testing.T) {
		eff, err := Merge(lockedBase(), json.RawMessage(`{"plugins":{"local-ssh":null}}`))
		require.NoError(t, err)
		assert.NotContains(t, eff.Plugins, "local-ssh")
	})

	t.Run("policies array replaced", func(t *testing.T) {
		eff, err := Merge(lockedBase(), json.RawMessage(`{"plugins":{"local-ssh":{"policies":["inline:x"]}}}`))
		require.NoError(t, err)
		assert.Equal(t, []string{"inline:x"}, eff.Plugins["local-ssh"].Policies)
	})

	t.Run("protocol_version null resets to auto", func(t *testing.T) {
		base := lockedBase()
		base.Plugins["local-ssh"].ProtocolVersion = 2
		eff, err := Merge(base, json.RawMessage(`{"plugins":{"local-ssh":{"protocol_version":null}}}`))
		require.NoError(t, err)
		assert.Equal(t, int32(0), eff.Plugins["local-ssh"].ProtocolVersion)
		assert.Equal(t, int32(2), base.Plugins["local-ssh"].ProtocolVersion, "base not mutated")
	})

	t.Run("policy_data numbers preserved exactly", func(t *testing.T) {
		base := lockedBase()
		base.Plugins["local-ssh"].PolicyData = map[string]any{"keep": json.Number("12345678901234567890")}
		eff, err := Merge(base, json.RawMessage(`{"plugins":{"local-ssh":{"policy_data":{"big":9007199254740993,"f":0.1}}}}`))
		require.NoError(t, err)
		pd := eff.Plugins["local-ssh"].PolicyData
		assert.Equal(t, json.Number("12345678901234567890"), pd["keep"])
		assert.Equal(t, json.Number("9007199254740993"), pd["big"])
		assert.Equal(t, json.Number("0.1"), pd["f"])
	})

	t.Run("yaml-decoded base values are normalized", func(t *testing.T) {
		base := lockedBase()
		base.Plugins["local-ssh"].PolicyData = map[string]any{"m": map[any]any{"a": 1}}
		eff, err := Merge(base, json.RawMessage(`{}`))
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"a": json.Number("1")}, eff.Plugins["local-ssh"].PolicyData["m"])
	})

	t.Run("policy bundles merge and module null deletes", func(t *testing.T) {
		base := lockedBase()
		base.PolicyBundles = map[string]*PolicyBundle{
			"ssh": {Extends: strPtr("ghcr.io/v/p:v1"), Modules: map[string]string{"a.rego": "package a", "b.rego": "package b"}},
		}
		eff, err := Merge(base, json.RawMessage(`{"policy_bundles":{"ssh":{"modules":{"a.rego":null,"c.rego":"package c"},"delete":["x.rego"]}}}`))
		require.NoError(t, err)
		b := eff.PolicyBundles["ssh"]
		require.NotNil(t, b)
		assert.Equal(t, map[string]string{"b.rego": "package b", "c.rego": "package c"}, b.Modules)
		assert.Equal(t, []string{"x.rego"}, b.Delete)
		assert.Equal(t, "ghcr.io/v/p:v1", *b.Extends)
	})

	t.Run("unknown overlay keys are ignored (non-strict)", func(t *testing.T) {
		eff, err := Merge(lockedBase(), json.RawMessage(`{"future_field":{"x":1},"plugins":{"local-ssh":{"future":true}}}`))
		require.NoError(t, err)
		assert.Equal(t, lockedBase().Plugins, eff.Plugins)
	})

	t.Run("errors", func(t *testing.T) {
		for _, o := range []string{`[1]`, `"x"`, `{"a"`, `{"plugins":{"x":{"config":{"port":2222}}}}`} {
			_, err := Merge(lockedBase(), json.RawMessage(o))
			assert.Error(t, err, o)
		}
	})
}

// FuzzMergeNeverChangesLocked checks that no overlay can change api, daemon or remote_config.
func FuzzMergeNeverChangesLocked(f *testing.F) {
	seeds := []string{
		``,
		`null`,
		`{}`,
		`{"api":{"url":"https://evil"}}`,
		`{"api":{"auth":{"client_id":"a","client_secret":"b"}}}`,
		`{"api":null}`,
		`{"daemon":false}`,
		`{"daemon":null}`,
		`{"remote_config":{"mode":"apply_all","allow_local_sources":true}}`,
		`{"remote_config":{"trusted_sources":["*"],"overridable_config_flags":["*"]}}`,
		`{"remote_config":null,"api":null,"daemon":false}`,
		`{"verbosity":2,"plugins":{"x":{"source":"ghcr.io/x/y:v1"}}}`,
		`{"plugins":{"api":{"config":{"daemon":"x"}}}}`,
		`{"policy_bundles":{"b":{"modules":{"a.rego":"package a"}}}}`,
		`{"API":{"url":"case"},"Daemon":false,"Remote_Config":{"mode":"apply_all"}}`,
		`{"api":1,"api":{"url":"dup"}}`,
		`[1,2]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, overlay []byte) {
		base := lockedBase()
		eff, err := Merge(base, overlay)
		if err != nil {
			return
		}
		want := lockedBase()
		if !assert.Equal(t, want.API, eff.API) ||
			!assert.Equal(t, want.Daemon, eff.Daemon) ||
			!assert.Equal(t, want.RemoteConfig, eff.RemoteConfig) {
			t.Fatalf("overlay %q changed a locked key", overlay)
		}
		assert.Equal(t, want, base, "base must not be mutated")
	})
}

// encoding/json matches field names case-insensitively; Merge must not let a differently
// cased key ("Plugins", "Source") smuggle values past the exact-name checks.
func TestMergeIgnoresMiscasedKeys(t *testing.T) {
	base := Config{Plugins: map[string]*Plugin{"ssh": {Source: "ghcr.io/x/ssh:v1"}}}
	eff, err := Merge(base, json.RawMessage(`{"Plugins":{"evil":{"source":"/tmp/evil"}},"plugins":{"ssh":{"Source":"/tmp/other"}}}`))
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if _, ok := eff.Plugins["evil"]; ok {
		t.Errorf("miscased root key added a plugin: %+v", eff.Plugins)
	}
	if got := eff.Plugins["ssh"].Source; got != "ghcr.io/x/ssh:v1" {
		t.Errorf("miscased plugin key changed the source to %q", got)
	}
}
