package agentcfg_test

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/stretchr/testify/assert"
)

func i64(v int64) *int64 { return &v }

func TestDeriveStatusAndSyncStatus(t *testing.T) {
	type tc struct {
		name     string
		instance relational.AgentInstance
		desired  int64
		status   string
		sync     string
	}
	cases := []tc{
		{
			name:     "never reported",
			instance: relational.AgentInstance{},
			desired:  2,
			status:   agentconfig.StatusUnknown,
			sync:     agentcfg.SyncUnknown,
		},
		{
			name:     "heartbeat-only row in apply mode is still unknown",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplySafe, HeartbeatConfigRevision: i64(1)},
			desired:  1,
			status:   agentconfig.StatusUnknown,
			sync:     agentcfg.SyncUnknown,
		},
		{
			name:     "never reported in report mode",
			instance: relational.AgentInstance{Mode: agentconfig.ModeReport},
			desired:  1,
			status:   agentconfig.StatusUnknown,
			sync:     agentcfg.SyncNotApplicable,
		},
		{
			name:     "applied and in sync",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplySafe, ReportedStatus: agentconfig.StatusApplied, AppliedRevision: i64(2)},
			desired:  2,
			status:   agentconfig.StatusApplied,
			sync:     agentcfg.SyncInSync,
		},
		{
			name:     "no revision yet, applied nil is revision 0",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplyAll, ReportedStatus: agentconfig.StatusApplied},
			desired:  0,
			status:   agentconfig.StatusApplied,
			sync:     agentcfg.SyncInSync,
		},
		{
			name:     "pending: behind and attempted nil",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplySafe, ReportedStatus: agentconfig.StatusApplied, AppliedRevision: i64(1)},
			desired:  2,
			status:   agentconfig.StatusPending,
			sync:     agentcfg.SyncOutOfSync,
		},
		{
			name:     "pending: applied nil",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplyAll, ReportedStatus: agentconfig.StatusApplied},
			desired:  1,
			status:   agentconfig.StatusPending,
			sync:     agentcfg.SyncOutOfSync,
		},
		{
			name: "pending: attempted older than desired",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplySafe, ReportedStatus: agentconfig.StatusRejected,
				AppliedRevision: i64(1), AttemptedRevision: i64(2)},
			desired: 3,
			status:  agentconfig.StatusPending,
			sync:    agentcfg.SyncOutOfSync,
		},
		{
			name: "rejected with attempted == desired stays rejected",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplySafe, ReportedStatus: agentconfig.StatusRejected,
				AppliedRevision: i64(1), AttemptedRevision: i64(2)},
			desired: 2,
			status:  agentconfig.StatusRejected,
			sync:    agentcfg.SyncOutOfSync,
		},
		{
			name: "failed with attempted == desired stays failed",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplyAll, ReportedStatus: agentconfig.StatusFailed,
				AttemptedRevision: i64(4)},
			desired: 4,
			status:  agentconfig.StatusFailed,
			sync:    agentcfg.SyncOutOfSync,
		},
		{
			name:     "report mode returns the reported status",
			instance: relational.AgentInstance{Mode: agentconfig.ModeReport, ReportedStatus: agentconfig.StatusNotApplicable, AppliedRevision: i64(0)},
			desired:  5,
			status:   agentconfig.StatusNotApplicable,
			sync:     agentcfg.SyncNotApplicable,
		},
		{
			name:     "off mode returns the reported status",
			instance: relational.AgentInstance{Mode: agentconfig.ModeOff, ReportedStatus: agentconfig.StatusNotApplicable},
			desired:  5,
			status:   agentconfig.StatusNotApplicable,
			sync:     agentcfg.SyncNotApplicable,
		},
		{
			name:     "ahead of desired (desired revision lower) is out of sync, not pending",
			instance: relational.AgentInstance{Mode: agentconfig.ModeApplySafe, ReportedStatus: agentconfig.StatusApplied, AppliedRevision: i64(3)},
			desired:  2,
			status:   agentconfig.StatusApplied,
			sync:     agentcfg.SyncOutOfSync,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.status, agentcfg.DeriveStatus(c.instance, c.desired))
			assert.Equal(t, c.sync, agentcfg.DeriveSyncStatus(c.instance, c.desired))
		})
	}
}

func TestIsStale(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seen := func(d time.Duration) relational.AgentInstance {
		return relational.AgentInstance{LastSeenAt: now.Add(-d)}
	}

	assert.False(t, agentcfg.IsStale(seen(0), now, agentcfg.Settings{}))
	assert.False(t, agentcfg.IsStale(seen(10*time.Minute), now, agentcfg.Settings{}), "exactly at the default boundary is fresh")
	assert.True(t, agentcfg.IsStale(seen(10*time.Minute+time.Second), now, agentcfg.Settings{}))
	assert.True(t, agentcfg.IsStale(seen(2*time.Minute), now, agentcfg.Settings{InstanceStaleAfter: time.Minute}))
	assert.False(t, agentcfg.IsStale(seen(30*time.Minute), now, agentcfg.Settings{InstanceStaleAfter: time.Hour}))
}

func TestSettingsWithDefaults(t *testing.T) {
	defaults := config.DefaultAgentsConfig()
	d := agentcfg.Settings{MaxInstancesPerAgent: -1}.WithDefaults()
	assert.Equal(t, defaults.InstanceStaleAfter, d.InstanceStaleAfter)
	assert.Equal(t, defaults.InstanceRetention, d.InstanceRetention)
	assert.Equal(t, defaults.OneShotInstanceRetention, d.OneShotInstanceRetention)
	assert.Equal(t, defaults.MaxInstancesPerAgent, d.MaxInstancesPerAgent)

	custom := agentcfg.Settings{InstanceStaleAfter: time.Minute, InstanceRetention: time.Hour, OneShotInstanceRetention: 2 * time.Minute, MaxInstancesPerAgent: 3}
	assert.Equal(t, custom, custom.WithDefaults())
}

func TestSettingsFromConfig(t *testing.T) {
	assert.Equal(t, agentcfg.Settings{}.WithDefaults(), agentcfg.SettingsFromConfig(nil))
	assert.Equal(t, agentcfg.Settings{}.WithDefaults(), agentcfg.SettingsFromConfig(&config.Config{}))

	got := agentcfg.SettingsFromConfig(&config.Config{Agents: &config.AgentsConfig{
		InstanceStaleAfter:       time.Minute,
		InstanceRetention:        2 * time.Hour,
		OneShotInstanceRetention: 3 * time.Minute,
		MaxInstancesPerAgent:     7,
	}})
	assert.Equal(t, agentcfg.Settings{
		InstanceStaleAfter:       time.Minute,
		InstanceRetention:        2 * time.Hour,
		OneShotInstanceRetention: 3 * time.Minute,
		MaxInstancesPerAgent:     7,
	}, got)

	partial := agentcfg.SettingsFromConfig(&config.Config{Agents: &config.AgentsConfig{MaxInstancesPerAgent: 9}})
	assert.Equal(t, 9, partial.MaxInstancesPerAgent)
	assert.Equal(t, config.DefaultAgentsConfig().InstanceRetention, partial.InstanceRetention)
}
