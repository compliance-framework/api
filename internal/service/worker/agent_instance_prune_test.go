package worker

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/compliance-framework/api/internal/service/relational/agentcfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPeriodicJobsFromConfig_AgentInstancePrune(t *testing.T) {
	logger := zap.NewNop().Sugar()

	assert.Len(t, periodicJobsFromConfig(&config.Config{}, logger), 0, "nil Agents config")

	disabled := config.DefaultAgentsConfig()
	disabled.InstancePruneEnabled = false
	assert.Len(t, periodicJobsFromConfig(&config.Config{Agents: disabled}, logger), 0)

	assert.Len(t, periodicJobsFromConfig(&config.Config{Agents: config.DefaultAgentsConfig()}, logger), 1)

	invalidSchedule := config.DefaultAgentsConfig()
	invalidSchedule.InstancePruneSchedule = "not a cron"
	assert.Len(t, periodicJobsFromConfig(&config.Config{Agents: invalidSchedule}, logger), 1, "falls back to the default schedule")
}

func TestAgentInstancePruneArgsKind(t *testing.T) {
	assert.Equal(t, "agent_instance_prune", AgentInstancePruneArgs{}.Kind())
	require.NotNil(t, NewAgentInstancePrunePeriodicJob("", zap.NewNop().Sugar()))
}

func TestAgentSettingsFromConfig(t *testing.T) {
	assert.Equal(t, agentcfg.Settings{}.WithDefaults(), agentSettingsFromConfig(nil))
	assert.Equal(t, agentcfg.Settings{}.WithDefaults(), agentSettingsFromConfig(&config.Config{}))

	got := agentSettingsFromConfig(&config.Config{Agents: &config.AgentsConfig{
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

	partial := agentSettingsFromConfig(&config.Config{Agents: &config.AgentsConfig{MaxInstancesPerAgent: 9}})
	assert.Equal(t, 9, partial.MaxInstancesPerAgent)
	assert.Equal(t, agentcfg.DefaultInstanceRetention, partial.InstanceRetention)
}
