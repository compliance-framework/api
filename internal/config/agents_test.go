package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestLoadAgentsConfigDefaults(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	cfg := LoadAgentsConfig()

	assert.Equal(t, 10*time.Minute, cfg.InstanceStaleAfter)
	assert.Equal(t, 720*time.Hour, cfg.InstanceRetention)
	assert.Equal(t, 24*time.Hour, cfg.OneShotInstanceRetention)
	assert.True(t, cfg.InstancePruneEnabled)
	assert.Equal(t, "0 17 * * * *", cfg.InstancePruneSchedule)
	assert.Equal(t, 500, cfg.MaxInstancesPerAgent)
	assert.Equal(t, DefaultAgentsConfig(), cfg)
}

func TestLoadAgentsConfigOverrides(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("agent_instance_stale_after", "5m")
	viper.Set("agent_instance_retention", "48h")
	viper.Set("agent_instance_oneshot_retention", "2h")
	viper.Set("agent_instance_prune_enabled", false)
	viper.Set("agent_instance_prune_schedule", "0 0 * * * *")
	viper.Set("agent_max_instances", 20)

	cfg := LoadAgentsConfig()

	assert.Equal(t, 5*time.Minute, cfg.InstanceStaleAfter)
	assert.Equal(t, 48*time.Hour, cfg.InstanceRetention)
	assert.Equal(t, 2*time.Hour, cfg.OneShotInstanceRetention)
	assert.False(t, cfg.InstancePruneEnabled)
	assert.Equal(t, "0 0 * * * *", cfg.InstancePruneSchedule)
	assert.Equal(t, 20, cfg.MaxInstancesPerAgent)
}

func TestLoadAgentsConfigFromEnv(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetEnvPrefix("ccf")
	viper.AutomaticEnv()
	t.Setenv("CCF_AGENT_INSTANCE_PRUNE_ENABLED", "false")
	t.Setenv("CCF_AGENT_MAX_INSTANCES", "3")
	t.Setenv("CCF_AGENT_INSTANCE_STALE_AFTER", "90s")

	cfg := LoadAgentsConfig()

	assert.False(t, cfg.InstancePruneEnabled)
	assert.Equal(t, 3, cfg.MaxInstancesPerAgent)
	assert.Equal(t, 90*time.Second, cfg.InstanceStaleAfter)
}

func TestLoadAgentsConfigIgnoresNonPositiveValues(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("agent_instance_stale_after", "0s")
	viper.Set("agent_instance_retention", "-1h")
	viper.Set("agent_instance_oneshot_retention", "0")
	viper.Set("agent_instance_prune_schedule", "")
	viper.Set("agent_max_instances", 0)

	cfg := LoadAgentsConfig()

	assert.Equal(t, DefaultAgentsConfig(), cfg)
}
