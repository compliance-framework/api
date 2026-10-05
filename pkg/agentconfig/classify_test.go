package agentconfig

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	srcSSH       = "ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0"
	srcSSHv2     = "ghcr.io/compliance-framework/plugin-local-ssh:v2.0.0"
	srcPolicies  = "ghcr.io/compliance-framework/plugin-local-ssh-policies:v1.0.0"
	srcCommon    = "ghcr.io/compliance-framework/common-policies:v1"
	srcDisabled  = "ghcr.io/other/plugin-disabled:v1"
	srcUntrusted = "ghcr.io/evil/plugin:v1"
	srcLocalUsed = "./local/policies"
	srcLocalNew  = "./bin/plugin"
)

func classifyBase() Config {
	return Config{
		Daemon:    true,
		Verbosity: 0,
		API: &APIConfig{
			URL:  "https://api.example.com",
			Auth: &APIAuth{ClientID: "0b3c1b8a-7c8e-4d53-9a52-9a3c1d1f2e10", ClientSecret: "s3cret"},
		},
		Plugins: map[string]*Plugin{
			"local-ssh": {
				Source:          srcSSH,
				Schedule:        strPtr("*/5 * * * *"),
				ProtocolVersion: 2,
				Policies:        []string{srcPolicies, srcCommon},
				Config:          map[string]string{"host": "localhost", "port": "22", "password": "${env:SSH_PASSWORD}"},
				Labels:          map[string]string{"env": "dev"},
				PolicyData:      map[string]any{"threshold": json.Number("5")},
			},
			"disabled": {
				Enabled:  boolPtr(false),
				Source:   srcDisabled,
				Policies: []string{srcLocalUsed},
			},
		},
	}
}

func testRC(mode string, mutate ...func(*RemoteConfig)) RemoteConfig {
	rc := RemoteConfig{
		Mode:                   mode,
		TrustedSources:         []string{"ghcr.io/compliance-framework/*"},
		OverridableConfigFlags: []string{"local-ssh:port"},
	}
	for _, m := range mutate {
		m(&rc)
	}
	return rc.Normalize(true)
}

func allowLocal(rc *RemoteConfig) { rc.AllowLocalSources = true }
func overridable(flags ...string) func(*RemoteConfig) {
	return func(rc *RemoteConfig) { rc.OverridableConfigFlags = flags }
}

func TestClassify(t *testing.T) {
	safe := testRC(ModeApplySafe)
	tests := []struct {
		name    string
		overlay string
		rc      RemoteConfig
		want    []Change
	}{
		{name: "empty overlay", overlay: `{}`, rc: safe, want: nil},
		{name: "null overlay", overlay: `null`, rc: safe, want: nil},
		{
			name:    "unchanged values produce no change",
			overlay: `{"verbosity":0,"plugins":{"local-ssh":{"source":"` + srcSSH + `","config":{"port":"22"},"enabled":true,"policies":["` + srcPolicies + `","` + srcCommon + `"]}}}`,
			rc:      safe,
			want:    nil,
		},
		// Locked keys.
		{name: "locked api", overlay: `{"api":{"url":"https://evil"}}`, rc: safe, want: []Change{{Path: "/api", Safety: Forbidden, Reason: ChangeReasonLockedKey}}},
		{name: "locked daemon null", overlay: `{"daemon":null}`, rc: safe, want: []Change{{Path: "/daemon", Safety: Forbidden, Reason: ChangeReasonLockedKey}}},
		{
			name:    "all locked keys",
			overlay: `{"remote_config":{"mode":"apply_all"},"daemon":false,"api":null}`,
			rc:      safe,
			want: []Change{
				{Path: "/api", Safety: Forbidden, Reason: ChangeReasonLockedKey},
				{Path: "/daemon", Safety: Forbidden, Reason: ChangeReasonLockedKey},
				{Path: "/remote_config", Safety: Forbidden, Reason: ChangeReasonLockedKey},
			},
		},
		// Logging.
		{name: "verbosity", overlay: `{"verbosity":2}`, rc: safe, want: []Change{{Path: "/verbosity", Safety: Safe, Reason: ChangeReasonLogging}}},
		{
			name:    "agent_evidence",
			overlay: `{"agent_evidence":{"enabled":false,"interval":"1m"}}`,
			rc:      safe,
			want: []Change{
				{Path: "/agent_evidence/enabled", Safety: Safe, Reason: ChangeReasonLogging},
				{Path: "/agent_evidence/interval", Safety: Safe, Reason: ChangeReasonLogging},
			},
		},
		// Plugin removal.
		{name: "plugin null reduces scope", overlay: `{"plugins":{"local-ssh":null}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh", Safety: Safe, Reason: ChangeReasonReducesScope}}},
		{name: "unknown plugin null is a no-op", overlay: `{"plugins":{"nope":null}}`, rc: safe, want: nil},
		// Data-only.
		{name: "schedule", overlay: `{"plugins":{"local-ssh":{"schedule":"@hourly"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/schedule", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "schedule null", overlay: `{"plugins":{"local-ssh":{"schedule":null}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/schedule", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "labels", overlay: `{"plugins":{"local-ssh":{"labels":{"env":"prod"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/labels", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "labels removed", overlay: `{"plugins":{"local-ssh":{"labels":null}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/labels", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "policy_behavior", overlay: `{"plugins":{"local-ssh":{"policy_behavior":{"deny":["warn"]}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policy_behavior", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "protocol_version", overlay: `{"plugins":{"local-ssh":{"protocol_version":1}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/protocol_version", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "protocol_version null", overlay: `{"plugins":{"local-ssh":{"protocol_version":null}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/protocol_version", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "enabled false", overlay: `{"plugins":{"local-ssh":{"enabled":false}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/enabled", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{name: "enabled true on a nil-enabled plugin is no change", overlay: `{"plugins":{"local-ssh":{"enabled":true}}}`, rc: safe, want: nil},
		{name: "re-enabling an untrusted plugin", overlay: `{"plugins":{"disabled":{"enabled":true}}}`, rc: safe, want: []Change{{Path: "/plugins/disabled/enabled", Safety: Unsafe, Reason: ChangeReasonReenablePlugin, Value: srcDisabled}}},
		{name: "re-enabling a trusted plugin", overlay: `{"plugins":{"disabled":{"enabled":null}}}`, rc: testRC(ModeApplySafe, func(rc *RemoteConfig) { rc.TrustedSources = []string{"ghcr.io/other/*"} }), want: []Change{{Path: "/plugins/disabled/enabled", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: srcDisabled}}},
		{name: "re-enabling with a new source", overlay: `{"plugins":{"disabled":{"enabled":true,"source":"` + srcSSHv2 + `"}}}`, rc: safe, want: []Change{
			{Path: "/plugins/disabled/enabled", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: srcSSHv2},
			{Path: "/plugins/disabled/source", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: srcSSHv2},
		}},
		{name: "policy_data", overlay: `{"plugins":{"local-ssh":{"policy_data":{"threshold":6}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policy_data", Safety: Safe, Reason: ChangeReasonDataOnly}}},
		{
			name:    "policy_data is always safe, even with secret-like keys and env-like strings",
			overlay: `{"plugins":{"local-ssh":{"policy_data":{"password":"x","ref":"${env:CCF_API_AUTH_CLIENT_SECRET}"}}}}`,
			rc:      testRC(ModeApplySafe, overridable()),
			want:    []Change{{Path: "/plugins/local-ssh/policy_data", Safety: Safe, Reason: ChangeReasonDataOnly}},
		},
		// Source.
		{name: "source trusted", overlay: `{"plugins":{"local-ssh":{"source":"` + srcSSHv2 + `"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: srcSSHv2}}},
		{name: "source untrusted", overlay: `{"plugins":{"local-ssh":{"source":"` + srcUntrusted + `"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Unsafe, Reason: ChangeReasonUntrustedSource, Value: srcUntrusted}}},
		{name: "source trust does not cross /", overlay: `{"plugins":{"local-ssh":{"source":"ghcr.io/compliance-framework/sub/p:v1"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Unsafe, Reason: ChangeReasonUntrustedSource, Value: "ghcr.io/compliance-framework/sub/p:v1"}}},
		// A disabled plugin's sources are not already used: the host chose not to run them.
		{name: "source used only by a disabled plugin", overlay: `{"plugins":{"local-ssh":{"source":"` + srcDisabled + `"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Unsafe, Reason: ChangeReasonUntrustedSource, Value: srcDisabled}}},
		{name: "new plugin with a disabled plugin's source", overlay: `{"plugins":{"bad2":{"source":"` + srcDisabled + `"}}}`, rc: safe, want: []Change{{Path: "/plugins/bad2/source", Safety: Unsafe, Reason: ChangeReasonUntrustedSource, Value: srcDisabled}}},
		{name: "source used only as a disabled plugin's policy", overlay: `{"plugins":{"local-ssh":{"source":"` + srcLocalUsed + `"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: srcLocalUsed}}},
		{name: "source already used as a policy", overlay: `{"plugins":{"local-ssh":{"source":"` + srcPolicies + `"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Safe, Reason: ChangeReasonAlreadyUsed, Value: srcPolicies}}},
		{name: "source local in apply_safe", overlay: `{"plugins":{"local-ssh":{"source":"` + srcLocalNew + `"}}}`, rc: testRC(ModeApplySafe, allowLocal), want: []Change{{Path: "/plugins/local-ssh/source", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: srcLocalNew}}},
		{name: "source local in apply_all without allow_local_sources", overlay: `{"plugins":{"local-ssh":{"source":"` + srcLocalNew + `"}}}`, rc: testRC(ModeApplyAll), want: []Change{{Path: "/plugins/local-ssh/source", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: srcLocalNew}}},
		{name: "source local in apply_all with allow_local_sources", overlay: `{"plugins":{"local-ssh":{"source":"` + srcLocalNew + `"}}}`, rc: testRC(ModeApplyAll, allowLocal), want: []Change{{Path: "/plugins/local-ssh/source", Safety: Unsafe, Reason: ChangeReasonNewLocalSource, Value: srcLocalNew}}},
		{name: "source OCI without tag is local", overlay: `{"plugins":{"local-ssh":{"source":"ghcr.io/compliance-framework/p"}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/source", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: "ghcr.io/compliance-framework/p"}}},
		// Policies.
		{name: "policies add an inline:-prefixed entry, a local path", overlay: `{"plugins":{"local-ssh":{"policies":["` + srcPolicies + `","` + srcCommon + `","inline:ssh-tuned"]}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policies", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: "inline:ssh-tuned"}}},
		{name: "policies add trusted OCI", overlay: `{"plugins":{"local-ssh":{"policies":["` + srcPolicies + `","ghcr.io/compliance-framework/extra:v1"]}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policies", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: "ghcr.io/compliance-framework/extra:v1"}}},
		{
			name:    "policies add several",
			overlay: `{"plugins":{"local-ssh":{"policies":["` + srcUntrusted + `","ghcr.io/compliance-framework/extra:v1","` + srcLocalUsed + `"]}}}`,
			rc:      safe,
			want: []Change{
				{Path: "/plugins/local-ssh/policies", Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: srcLocalUsed},
				{Path: "/plugins/local-ssh/policies", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: "ghcr.io/compliance-framework/extra:v1"},
				{Path: "/plugins/local-ssh/policies", Safety: Unsafe, Reason: ChangeReasonUntrustedSource, Value: srcUntrusted},
			},
		},
		{name: "policies removal", overlay: `{"plugins":{"local-ssh":{"policies":["` + srcCommon + `"]}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policies", Safety: Safe, Reason: ChangeReasonReducesScope}}},
		{name: "policies empty", overlay: `{"plugins":{"local-ssh":{"policies":[]}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policies", Safety: Safe, Reason: ChangeReasonReducesScope}}},
		{name: "policies null", overlay: `{"plugins":{"local-ssh":{"policies":null}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policies", Safety: Safe, Reason: ChangeReasonReducesScope}}},
		{name: "policies reorder", overlay: `{"plugins":{"local-ssh":{"policies":["` + srcCommon + `","` + srcPolicies + `"]}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/policies", Safety: Safe, Reason: ChangeReasonReducesScope}}},
		// Config.
		{name: "config overridable key", overlay: `{"plugins":{"local-ssh":{"config":{"port":"2222"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/port", Safety: Safe, Reason: ChangeReasonOverridableConfigFlag}}},
		{name: "config not overridable", overlay: `{"plugins":{"local-ssh":{"config":{"host":"other"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/host", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		{name: "config null is a change", overlay: `{"plugins":{"local-ssh":{"config":{"port":null}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/port", Safety: Safe, Reason: ChangeReasonOverridableConfigFlag}}},
		{name: "config new key", overlay: `{"plugins":{"local-ssh":{"config":{"timeout":"5s"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/timeout", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		{name: "config star glob", overlay: `{"plugins":{"local-ssh":{"config":{"host":"other"}}}}`, rc: testRC(ModeApplySafe, overridable("*")), want: []Change{{Path: "/plugins/local-ssh/config/host", Safety: Safe, Reason: ChangeReasonOverridableConfigFlag}}},
		{name: "config default empty list", overlay: `{"plugins":{"local-ssh":{"config":{"port":"2222"}}}}`, rc: RemoteConfig{Mode: ModeApplySafe}.Normalize(true), want: []Change{{Path: "/plugins/local-ssh/config/port", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		{name: "config scoped glob other plugin", overlay: `{"plugins":{"disabled":{"config":{"port":"2222"}}}}`, rc: safe, want: []Change{{Path: "/plugins/disabled/config/port", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		{name: "config key pointer escaping", overlay: `{"plugins":{"local-ssh":{"config":{"a/b~c":"x"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/a~1b~0c", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		// Env references.
		{name: "new env reference overrides overridable", overlay: `{"plugins":{"local-ssh":{"config":{"port":"${env:SSH_PORT}"}}}}`, rc: testRC(ModeApplySafe, overridable("*")), want: []Change{{Path: "/plugins/local-ssh/config/port", Safety: Unsafe, Reason: ChangeReasonNewEnvReference, Value: "SSH_PORT"}}},
		{name: "forbidden env reference", overlay: `{"plugins":{"local-ssh":{"config":{"host":"${env:CCF_API_AUTH_CLIENT_SECRET}"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/host", Safety: Forbidden, Reason: ChangeReasonForbiddenEnvReference, Value: "CCF_API_AUTH_CLIENT_SECRET"}}},
		{
			name:    "several new env references",
			overlay: `{"plugins":{"local-ssh":{"config":{"host":"${env:B}.${env:A}.${env:ccf_api_auth_x}"}}}}`,
			rc:      safe,
			want: []Change{
				{Path: "/plugins/local-ssh/config/host", Safety: Unsafe, Reason: ChangeReasonNewEnvReference, Value: "A"},
				{Path: "/plugins/local-ssh/config/host", Safety: Unsafe, Reason: ChangeReasonNewEnvReference, Value: "B"},
				{Path: "/plugins/local-ssh/config/host", Safety: Forbidden, Reason: ChangeReasonForbiddenEnvReference, Value: "ccf_api_auth_x"},
			},
		},
		{name: "same env reference already in base is not an env change", overlay: `{"plugins":{"local-ssh":{"config":{"password":"${env:SSH_PASSWORD}-2"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/password", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		{name: "same env reference already in base, overridable", overlay: `{"plugins":{"local-ssh":{"config":{"password":"${env:SSH_PASSWORD}-2"}}}}`, rc: testRC(ModeApplySafe, overridable("local-ssh:pass*")), want: []Change{{Path: "/plugins/local-ssh/config/password", Safety: Safe, Reason: ChangeReasonOverridableConfigFlag}}},
		{name: "env reference moved to another pointer is new", overlay: `{"plugins":{"local-ssh":{"config":{"port":"${env:SSH_PASSWORD}"}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/port", Safety: Unsafe, Reason: ChangeReasonNewEnvReference, Value: "SSH_PASSWORD"}}},
		{name: "env reference removed", overlay: `{"plugins":{"local-ssh":{"config":{"password":null}}}}`, rc: safe, want: []Change{{Path: "/plugins/local-ssh/config/password", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable}}},
		// New plugin: the class of its parts.
		{
			name:    "new plugin",
			overlay: `{"plugins":{"new":{"source":"ghcr.io/compliance-framework/new:v1","schedule":"@hourly","config":{"port":"1"},"policies":["` + srcCommon + `"]}}}`,
			rc:      safe,
			want: []Change{
				{Path: "/plugins/new/config/port", Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable},
				{Path: "/plugins/new/policies", Safety: Safe, Reason: ChangeReasonAlreadyUsed, Value: srcCommon},
				{Path: "/plugins/new/schedule", Safety: Safe, Reason: ChangeReasonDataOnly},
				{Path: "/plugins/new/source", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: "ghcr.io/compliance-framework/new:v1"},
			},
		},
		// Mixed: locked key plus a real change.
		{
			name:    "locked key and verbosity",
			overlay: `{"api":{"url":"x"},"verbosity":1}`,
			rc:      safe,
			want: []Change{
				{Path: "/api", Safety: Forbidden, Reason: ChangeReasonLockedKey},
				{Path: "/verbosity", Safety: Safe, Reason: ChangeReasonLogging},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := classifyBase()
			got, err := Classify(base, json.RawMessage(tt.overlay), tt.rc)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, classifyBase(), base, "base must not be mutated")
		})
	}
}

func TestClassifyErrors(t *testing.T) {
	rc := testRC(ModeApplySafe)
	for _, o := range []string{`[1]`, `"x"`, `{"a"`, `{"plugins":{"x":{"config":{"port":1}}}}`} {
		_, err := Classify(classifyBase(), json.RawMessage(o), rc)
		assert.Error(t, err, o)
	}
}

func TestWillApply(t *testing.T) {
	safeC := Change{Path: "/verbosity", Safety: Safe, Reason: ChangeReasonLogging}
	unsafeC := Change{Path: "/plugins/x/source", Safety: Unsafe, Reason: ChangeReasonUntrustedSource}
	forbiddenC := Change{Path: "/api", Safety: Forbidden, Reason: ChangeReasonLockedKey}

	tests := []struct {
		mode       string
		changes    []Change
		wantApply  bool
		wantReason string
	}{
		{mode: ModeOff, changes: nil, wantApply: false, wantReason: WillApplyReasonModeOff},
		{mode: ModeOff, changes: []Change{safeC}, wantApply: false, wantReason: WillApplyReasonModeOff},
		{mode: "", changes: []Change{safeC}, wantApply: false, wantReason: WillApplyReasonModeOff},
		{mode: "bogus", changes: []Change{safeC}, wantApply: false, wantReason: WillApplyReasonModeOff},
		{mode: ModeReport, changes: nil, wantApply: false, wantReason: WillApplyReasonModeReport},
		{mode: ModeReport, changes: []Change{forbiddenC}, wantApply: false, wantReason: WillApplyReasonModeReport},
		{mode: ModeApplySafe, changes: nil, wantApply: true},
		{mode: ModeApplySafe, changes: []Change{safeC}, wantApply: true},
		{mode: ModeApplySafe, changes: []Change{safeC, unsafeC}, wantApply: false, wantReason: ReasonUnsafeChanges},
		{mode: ModeApplySafe, changes: []Change{forbiddenC}, wantApply: false, wantReason: ReasonForbiddenChanges},
		{mode: ModeApplySafe, changes: []Change{unsafeC, forbiddenC, safeC}, wantApply: false, wantReason: ReasonForbiddenChanges},
		{mode: ModeApplyAll, changes: nil, wantApply: true},
		{mode: ModeApplyAll, changes: []Change{safeC, unsafeC}, wantApply: true},
		{mode: ModeApplyAll, changes: []Change{safeC, forbiddenC}, wantApply: false, wantReason: ReasonForbiddenChanges},
		{mode: ModeApplyAll, changes: []Change{unsafeC, forbiddenC}, wantApply: false, wantReason: ReasonForbiddenChanges},
	}
	for _, tt := range tests {
		ok, reason := WillApply(RemoteConfig{Mode: tt.mode}, tt.changes)
		assert.Equal(t, tt.wantApply, ok, "mode %q changes %v", tt.mode, tt.changes)
		assert.Equal(t, tt.wantReason, reason, "mode %q changes %v", tt.mode, tt.changes)
	}
}

func TestClassifyThenWillApply(t *testing.T) {
	overlay := json.RawMessage(`{"plugins":{"local-ssh":{"source":"` + srcLocalNew + `"}}}`)

	rcAll := testRC(ModeApplyAll, allowLocal)
	changes, err := Classify(classifyBase(), overlay, rcAll)
	require.NoError(t, err)
	ok, reason := WillApply(rcAll, changes)
	assert.True(t, ok)
	assert.Empty(t, reason)

	rcSafe := testRC(ModeApplySafe, allowLocal)
	changes, err = Classify(classifyBase(), overlay, rcSafe)
	require.NoError(t, err)
	ok, reason = WillApply(rcSafe, changes)
	assert.False(t, ok)
	assert.Equal(t, ReasonForbiddenChanges, reason)

	// No credentials: Normalize forces off.
	rcNoAuth := RemoteConfig{Mode: ModeApplyAll}.Normalize(false)
	ok, reason = WillApply(rcNoAuth, nil)
	assert.False(t, ok)
	assert.Equal(t, WillApplyReasonModeOff, reason)
}
