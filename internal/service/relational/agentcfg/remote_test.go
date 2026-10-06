package agentcfg

import (
	"testing"

	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/stretchr/testify/assert"
	"gorm.io/datatypes"
)

// The mode always comes from the validated top-level report mode, never from the reported
// remote-config block, which is not validated.
func TestReportedRemoteUsesRowMode(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		base   agentconfig.Config
	}{
		{name: "block says apply_all", remote: `{"mode":"apply_all","trusted_sources":["ghcr.io/x/*"]}`},
		{name: "block has an unknown mode", remote: `{"mode":"bogus","trusted_sources":["ghcr.io/x/*"]}`},
		{name: "no block, base says apply_all", base: agentconfig.Config{RemoteConfig: &agentconfig.RemoteConfig{Mode: agentconfig.ModeApplyAll, TrustedSources: []string{"ghcr.io/x/*"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := relational.AgentInstance{Mode: agentconfig.ModeApplySafe}
			if tc.remote != "" {
				row.RemoteConfig = datatypes.JSON(tc.remote)
			}
			rc := reportedRemote(row, tc.base)
			assert.Equal(t, agentconfig.ModeApplySafe, rc.Mode)
			assert.Equal(t, []string{"ghcr.io/x/*"}, rc.TrustedSources)
		})
	}
}
