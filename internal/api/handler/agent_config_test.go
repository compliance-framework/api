package handler

import (
	"encoding/json"
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPluginSource = "ghcr.io/compliance-framework/plugin-local-ssh:v1.0.0"

func strPtrT(s string) *string { return &s }

// badCronBase is a reported base whose file already has an invalid schedule on plugin x.
func badCronBase() agentconfig.Config {
	return agentconfig.Config{Plugins: map[string]*agentconfig.Plugin{
		"x": {Source: testPluginSource, Schedule: strPtrT("not a cron")},
		"y": {Source: testPluginSource, Schedule: strPtrT("@hourly")},
	}}
}

func TestSplitIntroduced(t *testing.T) {
	tests := []struct {
		name           string
		overlay        string
		wantIntroduced []string // paths
		wantFileOrigin []string // paths
	}{
		{
			name:           "unrelated overlay keeps the file error as a warning",
			overlay:        `{"verbosity":1}`,
			wantFileOrigin: []string{"/plugins/x/schedule"},
		},
		{
			name:           "replacing the bad cron with another bad cron is introduced",
			overlay:        `{"plugins":{"x":{"schedule":"also bad"}}}`,
			wantIntroduced: []string{"/plugins/x/schedule"},
		},
		{
			name:           "a new bad cron on another plugin is introduced",
			overlay:        `{"plugins":{"y":{"schedule":"nope"}}}`,
			wantIntroduced: []string{"/plugins/y/schedule"},
			wantFileOrigin: []string{"/plugins/x/schedule"},
		},
		{
			name:    "fixing the file error leaves nothing",
			overlay: `{"plugins":{"x":{"schedule":"@daily"}}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eff, introduced, fileOrigin := splitIntroduced(badCronBase(), json.RawMessage(tt.overlay))
			require.NotNil(t, eff)
			assert.Equal(t, tt.wantIntroduced, fieldPaths(introduced))
			assert.Equal(t, tt.wantFileOrigin, fieldPaths(fileOrigin))
			for _, e := range append(introduced, fileOrigin...) {
				assert.Equal(t, agentconfig.FieldCodeCron, e.Code)
			}
		})
	}
}

func TestValidateCandidateAndPreview_FileOriginErrorsDoNotBlock(t *testing.T) {
	base := agentcfg.InstanceBase{
		Instance:  relational.AgentInstance{InstanceID: uuid.New(), Mode: agentconfig.ModeApplySafe},
		Base:      badCronBase(),
		Remote:    agentconfig.RemoteConfig{Mode: agentconfig.ModeApplySafe},
		Validated: true,
	}

	ok := json.RawMessage(`{"verbosity":1}`)
	r := validateCandidate(ok, []agentcfg.InstanceBase{base})
	assert.False(t, r.blocking(), "file-origin errors must not block a save")
	assert.Empty(t, r.instances)

	p := previewInstance(base, ok, false)
	assert.Empty(t, p.Errors)
	require.Len(t, p.Warnings, 1)
	assert.Equal(t, "/plugins/x/schedule", p.Warnings[0].Path)
	assert.Equal(t, agentconfig.FieldCodeCron, p.Warnings[0].Code)
	assert.NotEqual(t, agentconfig.ReasonInvalidConfig, p.WillApplyReason)

	// Valid on its own (so it reaches the per-instance step), invalid once merged.
	bad := json.RawMessage(`{"plugins":{"y":{"source":null}}}`)
	r = validateCandidate(bad, []agentcfg.InstanceBase{base})
	assert.Empty(t, r.overlay)
	assert.True(t, r.blocking())
	require.Len(t, r.instances, 1)
	assert.Equal(t, []string{"/plugins/y/source"}, fieldPaths(r.instances[0].Errors))
	assert.Equal(t, []string{"/plugins/x/schedule"}, fieldPaths(r.instances[0].Warnings))

	p = previewInstance(base, bad, false)
	assert.Equal(t, []string{"/plugins/y/source"}, fieldPaths(p.Errors))
	assert.Equal(t, []string{"/plugins/x/schedule"}, fieldPaths(p.Warnings))
	assert.False(t, p.WillApply)
	assert.Equal(t, agentconfig.ReasonInvalidConfig, p.WillApplyReason)
}

func TestPreviewInstance_WarningsNeverNull(t *testing.T) {
	base := agentcfg.InstanceBase{
		Instance: relational.AgentInstance{InstanceID: uuid.New(), Mode: agentconfig.ModeApplySafe},
		Base:     agentconfig.Config{},
		Remote:   agentconfig.RemoteConfig{Mode: agentconfig.ModeApplySafe},
	}
	raw, err := json.Marshal(previewInstance(base, json.RawMessage(`{"verbosity":1}`), false))
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"warnings":[]`)
}

func fieldPaths(errs []agentconfig.FieldError) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Path)
	}
	return out
}
