package handler

import (
	"encoding/json"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
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
