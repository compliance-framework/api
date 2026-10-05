package agentconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateOverlayValid(t *testing.T) {
	overlays := []string{
		`{}`,
		`{"verbosity":0}`,
		`{"verbosity":2}`,
		`{"verbosity":null}`,
		`{"agent_evidence":{"enabled":true,"emit_on_run_completion":false,"interval":"5m"}}`,
		`{"agent_evidence":{"enabled":null,"emit_on_run_completion":null,"interval":null}}`,
		`{"agent_evidence":{"interval":"0s"}}`,
		`{"agent_evidence":null}`,
		`{"plugins":null}`,
		`{"plugins":{"local-ssh":null}}`,
		`{"plugins":{"GitHub":null}}`, // pattern is checked only for non-null plugin entries
		`{"plugins":{"local-ssh":{
			"enabled": false,
			"protocol_version": 2,
			"schedule": "*/5 * * * *",
			"source": "ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0",
			"policies": ["ghcr.io/compliance-framework/plugin-local-ssh-policies:v1.0.0", "./policies/extra"],
			"config": {"port": "2222", "host": null, "password": "${env:SSH_PASSWORD}", "dsn": "user=${env:U}@h"},
			"labels": {"env": "prod", "old": null},
			"policy_data": {"threshold": 5, "nested": {"a": [1, true]}},
			"policy_behavior": {"deny": ["warn"], "old": null}
		}}}`,
		`{"plugins":{"x":{"protocol_version":1}}}`,
		`{"plugins":{"x":{"protocol_version":null}}}`,
		`{"plugins":{"x":{"schedule":"@hourly"}}}`,
		`{"plugins":{"x":{"schedule":null}}}`,
		`{"plugins":{"x":{"enabled":null,"source":null,"policies":null,"config":null,"labels":null,"policy_data":null,"policy_behavior":null}}}`,
		`{"plugins":{"x":{"policies":[]}}}`,
	}
	for _, o := range overlays {
		t.Run(o, func(t *testing.T) {
			assert.NoError(t, ValidateOverlay(json.RawMessage(o)))
		})
	}
}

func TestValidateOverlayRules(t *testing.T) {
	tests := []struct {
		name     string
		overlay  string
		path     string
		code     string
		contains string
	}{
		// O1
		{name: "O1 array", overlay: `[]`, path: "", code: FieldCodeParse},
		{name: "O1 string", overlay: `"x"`, path: "", code: FieldCodeParse},
		{name: "O1 null", overlay: `null`, path: "", code: FieldCodeParse},
		{name: "O1 invalid json", overlay: `{"a":`, path: "", code: FieldCodeParse},
		// O3
		{name: "O3 api", overlay: `{"api":{"url":"x"}}`, path: "/api", code: FieldCodeLockedKey},
		{name: "O3 api null", overlay: `{"api":null}`, path: "/api", code: FieldCodeLockedKey},
		{name: "O3 daemon", overlay: `{"daemon":true}`, path: "/daemon", code: FieldCodeLockedKey},
		{name: "O3 daemon null", overlay: `{"daemon":null}`, path: "/daemon", code: FieldCodeLockedKey},
		{name: "O3 remote_config", overlay: `{"remote_config":{"mode":"apply_all"}}`, path: "/remote_config", code: FieldCodeLockedKey},
		{name: "O3 remote_config null", overlay: `{"remote_config":null}`, path: "/remote_config", code: FieldCodeLockedKey},
		// O4
		{name: "O4 unknown root key plugin", overlay: `{"plugin":{}}`, path: "/plugin", code: FieldCodeUnknownField},
		{name: "O4 unknown root key null", overlay: `{"foo":null}`, path: "/foo", code: FieldCodeUnknownField},
		{name: "O4 case matters", overlay: `{"Plugins":{}}`, path: "/Plugins", code: FieldCodeUnknownField},
		{name: "O4 unknown plugin key", overlay: `{"plugins":{"x":{"sorce":"s"}}}`, path: "/plugins/x/sorce", code: FieldCodeUnknownField},
		{name: "O4 unknown plugin key null", overlay: `{"plugins":{"x":{"sorce":null}}}`, path: "/plugins/x/sorce", code: FieldCodeUnknownField},
		{name: "O4 unknown agent_evidence key", overlay: `{"agent_evidence":{"on":true}}`, path: "/agent_evidence/on", code: FieldCodeUnknownField},
		{name: "O4 policy_bundles is unknown", overlay: `{"policy_bundles":{"b":{"modules":{}}}}`, path: "/policy_bundles", code: FieldCodeUnknownField},
		{name: "O4 policy_bundles null is unknown", overlay: `{"policy_bundles":null}`, path: "/policy_bundles", code: FieldCodeUnknownField},
		// O5
		{name: "O5 config number", overlay: `{"plugins":{"x":{"config":{"port":2222}}}}`, path: "/plugins/x/config/port", code: FieldCodeInvalidType, contains: "must be a string"},
		{name: "O5 config bool", overlay: `{"plugins":{"x":{"config":{"tls":false}}}}`, path: "/plugins/x/config/tls", code: FieldCodeInvalidType, contains: "must be a string"},
		{name: "O5 config object", overlay: `{"plugins":{"x":{"config":{"a":{}}}}}`, path: "/plugins/x/config/a", code: FieldCodeInvalidType, contains: "must be a string"},
		{name: "O5 config not object", overlay: `{"plugins":{"x":{"config":"a=b"}}}`, path: "/plugins/x/config", code: FieldCodeInvalidType},
		{name: "O5 labels bool", overlay: `{"plugins":{"x":{"labels":{"env":true}}}}`, path: "/plugins/x/labels/env", code: FieldCodeInvalidType, contains: "must be a string"},
		{name: "O5 verbosity string", overlay: `{"verbosity":"1"}`, path: "/verbosity", code: FieldCodeInvalidType},
		{name: "O5 verbosity float", overlay: `{"verbosity":1.5}`, path: "/verbosity", code: FieldCodeInvalidType},
		{name: "O5 verbosity too big", overlay: `{"verbosity":3}`, path: "/verbosity", code: FieldCodeInvalidValue},
		{name: "O5 verbosity negative", overlay: `{"verbosity":-1}`, path: "/verbosity", code: FieldCodeInvalidValue},
		{name: "O5 evidence enabled string", overlay: `{"agent_evidence":{"enabled":"yes"}}`, path: "/agent_evidence/enabled", code: FieldCodeInvalidType},
		{name: "O5 evidence emit number", overlay: `{"agent_evidence":{"emit_on_run_completion":1}}`, path: "/agent_evidence/emit_on_run_completion", code: FieldCodeInvalidType},
		{name: "O5 evidence interval bad", overlay: `{"agent_evidence":{"interval":"soon"}}`, path: "/agent_evidence/interval", code: FieldCodeDuration},
		{name: "O5 evidence interval negative", overlay: `{"agent_evidence":{"interval":"-1s"}}`, path: "/agent_evidence/interval", code: FieldCodeDuration},
		{name: "O5 evidence interval number", overlay: `{"agent_evidence":{"interval":60}}`, path: "/agent_evidence/interval", code: FieldCodeInvalidType},
		{name: "O5 evidence not object", overlay: `{"agent_evidence":true}`, path: "/agent_evidence", code: FieldCodeInvalidType},
		{name: "O5 enabled string", overlay: `{"plugins":{"x":{"enabled":"true"}}}`, path: "/plugins/x/enabled", code: FieldCodeInvalidType},
		{name: "O5 protocol_version explicit 0", overlay: `{"plugins":{"x":{"protocol_version":0}}}`, path: "/plugins/x/protocol_version", code: FieldCodeInvalidValue, contains: "null"},
		{name: "O5 protocol_version 3", overlay: `{"plugins":{"x":{"protocol_version":3}}}`, path: "/plugins/x/protocol_version", code: FieldCodeInvalidValue},
		{name: "O5 protocol_version string", overlay: `{"plugins":{"x":{"protocol_version":"2"}}}`, path: "/plugins/x/protocol_version", code: FieldCodeInvalidType},
		{name: "O5 schedule number", overlay: `{"plugins":{"x":{"schedule":5}}}`, path: "/plugins/x/schedule", code: FieldCodeInvalidType},
		{name: "O5 policy_behavior value not array", overlay: `{"plugins":{"x":{"policy_behavior":{"deny":"warn"}}}}`, path: "/plugins/x/policy_behavior/deny", code: FieldCodeInvalidType},
		{name: "O5 policy_behavior item not string", overlay: `{"plugins":{"x":{"policy_behavior":{"deny":[1]}}}}`, path: "/plugins/x/policy_behavior/deny/0", code: FieldCodeInvalidType},
		{name: "O5 policy_behavior not object", overlay: `{"plugins":{"x":{"policy_behavior":[]}}}`, path: "/plugins/x/policy_behavior", code: FieldCodeInvalidType},
		{name: "O5 policy_data not object", overlay: `{"plugins":{"x":{"policy_data":[1]}}}`, path: "/plugins/x/policy_data", code: FieldCodeInvalidType},
		{name: "O5 policies not array", overlay: `{"plugins":{"x":{"policies":"a"}}}`, path: "/plugins/x/policies", code: FieldCodeInvalidType},
		{name: "O5 policies item not string", overlay: `{"plugins":{"x":{"policies":[1]}}}`, path: "/plugins/x/policies/0", code: FieldCodeInvalidType},
		{name: "O5 plugin not object", overlay: `{"plugins":{"x":"ghcr.io/x/y:v1"}}`, path: "/plugins/x", code: FieldCodeInvalidType},
		{name: "O5 plugins not object", overlay: `{"plugins":[]}`, path: "/plugins", code: FieldCodeInvalidType},
		{name: "O5 source number", overlay: `{"plugins":{"x":{"source":1}}}`, path: "/plugins/x/source", code: FieldCodeInvalidType},
		// O6
		{name: "O6 plugin name upper case", overlay: `{"plugins":{"GitHub":{"source":"ghcr.io/x/y:v1"}}}`, path: "/plugins/GitHub", code: FieldCodePattern},
		{name: "O6 plugin name leading dash", overlay: `{"plugins":{"-x":{}}}`, path: "/plugins/-x", code: FieldCodePattern},
		{name: "O6 plugin name too long", overlay: `{"plugins":{"` + strings.Repeat("a", 64) + `":{}}}`, path: "/plugins/" + strings.Repeat("a", 64), code: FieldCodePattern},
		// O7
		{name: "O7 bad cron", overlay: `{"plugins":{"x":{"schedule":"every minute"}}}`, path: "/plugins/x/schedule", code: FieldCodeCron},
		{name: "O7 six-field cron", overlay: `{"plugins":{"x":{"schedule":"0 */5 * * * *"}}}`, path: "/plugins/x/schedule", code: FieldCodeCron},
		{name: "O7 empty cron", overlay: `{"plugins":{"x":{"schedule":""}}}`, path: "/plugins/x/schedule", code: FieldCodeCron},
		// O8
		{name: "O8 empty source", overlay: `{"plugins":{"x":{"source":""}}}`, path: "/plugins/x/source", code: FieldCodeSource},
		{name: "O8 blank source", overlay: `{"plugins":{"x":{"source":"  "}}}`, path: "/plugins/x/source", code: FieldCodeSource},
		{name: "O8 empty policy entry", overlay: `{"plugins":{"x":{"policies":["ghcr.io/x/p:v1",""]}}}`, path: "/plugins/x/policies/1", code: FieldCodeSource},
		// O9
		{name: "O9 env in policy_data", overlay: `{"plugins":{"x":{"policy_data":{"t":"${env:X}"}}}}`, path: "/plugins/x/policy_data/t", code: FieldCodeEnvLocation},
		{name: "O9 env in nested policy_data array", overlay: `{"plugins":{"x":{"policy_data":{"a":["${env:X}"]}}}}`, path: "/plugins/x/policy_data/a/0", code: FieldCodeEnvLocation},
		{name: "O9 env in labels", overlay: `{"plugins":{"x":{"labels":{"t":"a-${env:X}"}}}}`, path: "/plugins/x/labels/t", code: FieldCodeEnvLocation},
		{name: "O9 env in source", overlay: `{"plugins":{"x":{"source":"ghcr.io/${env:ORG}/y:v1"}}}`, path: "/plugins/x/source", code: FieldCodeEnvLocation},
		{name: "O9 forbidden env", overlay: `{"plugins":{"x":{"config":{"s":"${env:CCF_API_AUTH_CLIENT_SECRET}"}}}}`, path: "/plugins/x/config/s", code: FieldCodeForbiddenEnv},
		{name: "O9 forbidden env embedded lower case", overlay: `{"plugins":{"x":{"config":{"s":"a${env:ccf_api_auth_client_id}b"}}}}`, path: "/plugins/x/config/s", code: FieldCodeForbiddenEnv},
		// O10
		{name: "O10 masked config", overlay: `{"plugins":{"x":{"config":{"password":"••••"}}}}`, path: "/plugins/x/config/password", code: FieldCodeMaskedValue},
		{name: "O10 masked policy_data", overlay: `{"plugins":{"x":{"policy_data":{"a":{"token":"••••"}}}}}`, path: "/plugins/x/policy_data/a/token", code: FieldCodeMaskedValue},
		// O11
		{name: "O11 NUL in config value", overlay: `{"plugins":{"x":{"config":{"a":"b\u0000c"}}}}`, path: "/plugins/x/config/a", code: FieldCodeInvalidValue, contains: "NUL"},
		{name: "O11 NUL in nested policy_data", overlay: `{"plugins":{"x":{"policy_data":{"a":["\u0000"]}}}}`, path: "/plugins/x/policy_data/a/0", code: FieldCodeInvalidValue, contains: "NUL"},
		{name: "O11 NUL in key", overlay: `{"plugins":{"x":{"labels":{"a\u0000":"b"}}}}`, path: "/plugins/x/labels/a\x00", code: FieldCodeInvalidValue, contains: "NUL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fe := requireFieldError(t, ValidateOverlay(json.RawMessage(tt.overlay)), tt.path, tt.code)
			if tt.contains != "" {
				assert.Contains(t, fe.Message, tt.contains)
			}
		})
	}
}

func TestValidateOverlayPortMessage(t *testing.T) {
	err := ValidateOverlay(json.RawMessage(`{"plugins":{"x":{"config":{"port":2222}}}}`))
	errs := fieldErrors(t, err)
	require.Len(t, errs, 1)
	assert.Equal(t, FieldError{Path: "/plugins/x/config/port", Code: FieldCodeInvalidType, Message: "must be a string"}, errs[0])
	assert.Contains(t, err.Error(), "/plugins/x/config/port")
	assert.Contains(t, err.Error(), "must be a string")
}

func TestValidateOverlaySize(t *testing.T) {
	// labelOverlay returns a valid overlay whose compact size is exactly n bytes.
	labelOverlay := func(t *testing.T, prefix string, n int) string {
		t.Helper()
		head := `{` + prefix + `"plugins":{"x":{"labels":{"a":"`
		tail := `"}}}}`
		pad := n - len(head) - len(tail)
		require.Positive(t, pad)
		o := head + strings.Repeat("v", pad) + tail
		require.Len(t, o, n)
		return o
	}

	t.Run("limit", func(t *testing.T) {
		assert.NoError(t, ValidateOverlay(json.RawMessage(labelOverlay(t, "", MaxOverlayBytes))))
		requireFieldError(t, ValidateOverlay(json.RawMessage(labelOverlay(t, "", MaxOverlayBytes+1))), "", FieldCodeSize)
	})
	t.Run("size is measured on compact JSON", func(t *testing.T) {
		o := labelOverlay(t, "", MaxOverlayBytes)
		pretty := strings.Replace(o, `{"plugins"`, "{\n    \"plugins\"", 1)
		require.Greater(t, len(pretty), MaxOverlayBytes)
		assert.NoError(t, ValidateOverlay(json.RawMessage(pretty)))
	})
}

func TestValidateOverlayErrorsSorted(t *testing.T) {
	err := ValidateOverlay(json.RawMessage(`{"verbosity":9,"api":{},"plugins":{"x":{"config":{"b":1,"a":true}}}}`))
	errs := fieldErrors(t, err)
	paths := make([]string, 0, len(errs))
	for _, e := range errs {
		paths = append(paths, e.Path)
	}
	assert.Equal(t, []string{"/api", "/plugins/x/config/a", "/plugins/x/config/b", "/verbosity"}, paths)
}

// validConfig is a complete, valid effective config.
func validConfig() Config {
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
			OverridableConfigFlags: []string{"local-ssh:port", "*"},
		},
		AgentEvidence: &EvidenceConfig{Interval: "5m"},
		Plugins: map[string]*Plugin{
			"local-ssh": {
				Source:          "ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0",
				Schedule:        strPtr("*/5 * * * *"),
				ProtocolVersion: 2,
				Policies:        []string{"ghcr.io/compliance-framework/plugin-local-ssh-policies:v1.0.0"},
				Config:          map[string]string{"host": "localhost", "password": "${env:SSH_PASSWORD}"},
				PolicyData:      map[string]any{"threshold": json.Number("5")},
			},
		},
	}
}

func TestValidateValid(t *testing.T) {
	c := validConfig()
	require.NoError(t, c.Validate())
	require.NoError(t, c.ValidateEditable())

	noAuth := validConfig()
	noAuth.API.Auth = nil
	assert.NoError(t, noAuth.Validate(), "auth is optional")

	noRC := validConfig()
	noRC.RemoteConfig = nil
	assert.NoError(t, noRC.Validate(), "remote_config is optional")

	descriptor := validConfig()
	descriptor.Plugins["local-ssh"].Schedule = strPtr("@hourly")
	assert.NoError(t, descriptor.Validate())

	auto := validConfig()
	auto.Plugins["local-ssh"].ProtocolVersion = 0
	assert.NoError(t, auto.Validate(), "protocol_version 0 = auto in an effective config")

	empty := Config{API: &APIConfig{URL: "http://x"}}
	assert.NoError(t, empty.Validate())
}

func TestValidateEditableErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
		path   string
		code   string
	}{
		{name: "negative verbosity", mutate: func(c *Config) { c.Verbosity = -1 }, path: "/verbosity", code: FieldCodeInvalidValue},
		{name: "bad evidence interval", mutate: func(c *Config) { c.AgentEvidence.Interval = "often" }, path: "/agent_evidence/interval", code: FieldCodeDuration},
		{name: "negative evidence interval", mutate: func(c *Config) { c.AgentEvidence.Interval = "-5m" }, path: "/agent_evidence/interval", code: FieldCodeDuration},
		{name: "nil plugin", mutate: func(c *Config) { c.Plugins["other"] = nil }, path: "/plugins/other", code: FieldCodeRequired},
		{name: "empty source", mutate: func(c *Config) { c.Plugins["local-ssh"].Source = "" }, path: "/plugins/local-ssh/source", code: FieldCodeRequired},
		{name: "bad cron", mutate: func(c *Config) { c.Plugins["local-ssh"].Schedule = strPtr("nope") }, path: "/plugins/local-ssh/schedule", code: FieldCodeCron},
		{name: "six-field cron", mutate: func(c *Config) { c.Plugins["local-ssh"].Schedule = strPtr("0 */5 * * * *") }, path: "/plugins/local-ssh/schedule", code: FieldCodeCron},
		{name: "protocol_version 3", mutate: func(c *Config) { c.Plugins["local-ssh"].ProtocolVersion = 3 }, path: "/plugins/local-ssh/protocol_version", code: FieldCodeInvalidValue},
		{name: "protocol_version negative", mutate: func(c *Config) { c.Plugins["local-ssh"].ProtocolVersion = -1 }, path: "/plugins/local-ssh/protocol_version", code: FieldCodeInvalidValue},
		{name: "empty policy entry", mutate: func(c *Config) { c.Plugins["local-ssh"].Policies = append(c.Plugins["local-ssh"].Policies, "") }, path: "/plugins/local-ssh/policies/1", code: FieldCodeSource},
		{name: "env in policy_data", mutate: func(c *Config) { c.Plugins["local-ssh"].PolicyData = map[string]any{"t": "${env:X}"} }, path: "/plugins/local-ssh/policy_data/t", code: FieldCodeEnvLocation},
		{name: "env in labels", mutate: func(c *Config) { c.Plugins["local-ssh"].Labels = map[string]string{"t": "${env:X}"} }, path: "/plugins/local-ssh/labels/t", code: FieldCodeEnvLocation},
		{name: "forbidden env in config", mutate: func(c *Config) { c.Plugins["local-ssh"].Config["s"] = "${env:CCF_API_AUTH_CLIENT_SECRET}" }, path: "/plugins/local-ssh/config/s", code: FieldCodeForbiddenEnv},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			requireFieldError(t, c.ValidateEditable(), tt.path, tt.code)
			requireFieldError(t, c.Validate(), tt.path, tt.code)
		})
	}
}

func TestValidateEditableIgnoresLockedBlocks(t *testing.T) {
	c := validConfig()
	c.API = nil
	c.RemoteConfig = &RemoteConfig{Mode: "bogus", PollInterval: "1s", TrustedSources: []string{"["}}
	assert.NoError(t, c.ValidateEditable())
	assert.Error(t, c.Validate())
}

func TestValidateEditableRedactedBase(t *testing.T) {
	c := validConfig()
	c.Plugins["local-ssh"].Config["token"] = "abc"
	c.Plugins["local-ssh"].Config["user"] = "root"
	c.Plugins["local-ssh"].PolicyData["api_key"] = "k"
	red := Redact(c, WithMaskedPointers("/plugins/local-ssh/config/user"))
	require.Empty(t, red.API.Auth.ClientSecret)
	require.Equal(t, MaskedValue, red.Plugins["local-ssh"].Config["user"])
	assert.NoError(t, red.ValidateEditable(), "masked values and a missing client secret are fine")
	requireFieldError(t, red.Validate(), "/api/auth", FieldCodeRequired)
}

func TestValidateAPIAndRemoteConfig(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
		path   string
		code   string
	}{
		{name: "no api", mutate: func(c *Config) { c.API = nil }, path: "/api", code: FieldCodeRequired},
		{name: "no url", mutate: func(c *Config) { c.API.URL = " " }, path: "/api/url", code: FieldCodeRequired},
		{name: "partial auth: no secret", mutate: func(c *Config) { c.API.Auth.ClientSecret = "" }, path: "/api/auth", code: FieldCodeRequired},
		{name: "partial auth: no id", mutate: func(c *Config) { c.API.Auth.ClientID = "" }, path: "/api/auth", code: FieldCodeRequired},
		{name: "client_id not a uuid", mutate: func(c *Config) { c.API.Auth.ClientID = "agent-1" }, path: "/api/auth/client_id", code: FieldCodeInvalidValue},
		{name: "bad mode", mutate: func(c *Config) { c.RemoteConfig.Mode = "apply" }, path: "/remote_config/mode", code: FieldCodeInvalidValue},
		{name: "poll_interval too small", mutate: func(c *Config) { c.RemoteConfig.PollInterval = "14s" }, path: "/remote_config/poll_interval", code: FieldCodeDuration},
		{name: "poll_interval garbage", mutate: func(c *Config) { c.RemoteConfig.PollInterval = "sometimes" }, path: "/remote_config/poll_interval", code: FieldCodeDuration},
		{name: "bad trusted source glob", mutate: func(c *Config) { c.RemoteConfig.TrustedSources = []string{"ghcr.io/*", "ghcr.io/[x"} }, path: "/remote_config/trusted_sources/1", code: FieldCodePattern},
		{name: "bad overridable key glob", mutate: func(c *Config) { c.RemoteConfig.OverridableConfigFlags = []string{"[port"} }, path: "/remote_config/overridable_config_flags/0", code: FieldCodePattern},
		{name: "bad overridable plugin glob", mutate: func(c *Config) { c.RemoteConfig.OverridableConfigFlags = []string{"port", "[x:port"} }, path: "/remote_config/overridable_config_flags/1", code: FieldCodePattern},
		{name: "bad overridable scoped key glob", mutate: func(c *Config) { c.RemoteConfig.OverridableConfigFlags = []string{"x:[port"} }, path: "/remote_config/overridable_config_flags/0", code: FieldCodePattern},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(&c)
			requireFieldError(t, c.Validate(), tt.path, tt.code)
			assert.NoError(t, c.ValidateEditable())
		})
	}

	t.Run("valid remote_config variants", func(t *testing.T) {
		for _, mode := range []string{"", ModeOff, ModeReport, ModeApplySafe, ModeApplyAll} {
			c := validConfig()
			c.RemoteConfig.Mode = mode
			c.RemoteConfig.PollInterval = "15s"
			assert.NoError(t, c.Validate(), mode)
		}
	})
}

func TestParseSchedule(t *testing.T) {
	for _, ok := range []string{"* * * * *", "*/5 * * * *", "0 3 * * 1-5", "@hourly", "@daily", "@every 5m"} {
		_, err := ParseSchedule(ok)
		assert.NoError(t, err, ok)
	}
	for _, bad := range []string{"", "0 */5 * * * *", "* * * *", "nope", "61 * * * *"} {
		_, err := ParseSchedule(bad)
		assert.Error(t, err, bad)
	}
}

func TestValidationErrorsError(t *testing.T) {
	assert.Equal(t, "no validation errors", ValidationErrors{}.Error())
	assert.Equal(t, "/: bad; /a: worse", ValidationErrors{{Path: "", Message: "bad"}, {Path: "/a", Message: "worse"}}.Error())
}
