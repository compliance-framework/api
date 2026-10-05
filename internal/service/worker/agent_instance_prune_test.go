package worker

import (
	"testing"

	"github.com/compliance-framework/api/internal/config"
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
