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

// Instances that share a BaseKey are validated once, and every one of them is still listed
// with the errors the overlay introduces on that base.
func TestValidateCandidateAttributesSharedBaseErrors(t *testing.T) {
	shared := badCronBase()
	good := agentconfig.Config{Plugins: map[string]*agentconfig.Plugin{
		"z": {Source: testPluginSource, Schedule: strPtrT("@hourly")},
	}}
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	bases := []agentcfg.InstanceBase{
		{Instance: relational.AgentInstance{InstanceID: ids[0], Hostname: strPtrT("a")}, Base: shared, BaseKey: "k1"},
		{Instance: relational.AgentInstance{InstanceID: ids[1], Hostname: strPtrT("b")}, Base: shared, BaseKey: "k1"},
		{Instance: relational.AgentInstance{InstanceID: ids[2], Hostname: strPtrT("c")}, Base: good, BaseKey: "k2"},
		{Instance: relational.AgentInstance{InstanceID: ids[3], Hostname: strPtrT("d")}, Base: shared}, // no key: validated on its own
	}
	// Plugin z has a source only in the k2 base: elsewhere the overlay adds it without one.
	r := validateCandidate(json.RawMessage(`{"plugins":{"z":{"schedule":"* * * * *"}}}`), bases)
	require.Empty(t, r.overlay)
	require.Len(t, r.instances, 3, "the k2 base already has plugin z")
	for i, want := range []struct {
		id   uuid.UUID
		host string
	}{{ids[0], "a"}, {ids[1], "b"}, {ids[3], "d"}} {
		got := r.instances[i]
		assert.Equal(t, want.id.String(), got.InstanceID)
		assert.Equal(t, want.host, *got.Hostname)
		assert.Equal(t, []string{"/plugins/z/source"}, fieldPaths(got.Errors))
		assert.Equal(t, []string{"/plugins/x/schedule"}, fieldPaths(got.Warnings), "file-origin")
	}
}
