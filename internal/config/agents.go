package config

import (
	"time"

	"github.com/spf13/viper"
)

// AgentsConfig tunes agent remote configuration: instance freshness, retention, pruning and
// the per-agent instance cap (R14, R37).
type AgentsConfig struct {
	// InstanceStaleAfter: an instance is fresh when seen (heartbeat or report) within this
	// window. CCF_AGENT_INSTANCE_STALE_AFTER, default 10m.
	InstanceStaleAfter time.Duration `json:"instanceStaleAfter"`
	// InstanceRetention: daemon (or unknown) instances not seen for this long are pruned.
	// CCF_AGENT_INSTANCE_RETENTION, default 720h.
	InstanceRetention time.Duration `json:"instanceRetention"`
	// OneShotInstanceRetention: daemon=false instances not seen for this long are pruned.
	// CCF_AGENT_INSTANCE_ONESHOT_RETENTION, default 24h.
	OneShotInstanceRetention time.Duration `json:"oneShotInstanceRetention"`
	// InstancePruneEnabled schedules the prune job (needs the worker service).
	// CCF_AGENT_INSTANCE_PRUNE_ENABLED, default true.
	InstancePruneEnabled bool `json:"instancePruneEnabled"`
	// InstancePruneSchedule is the River (6-field, seconds first) cron of the prune job.
	// CCF_AGENT_INSTANCE_PRUNE_SCHEDULE, default "0 17 * * * *" (hourly). The job is
	// deduplicated per hour, so it runs at most hourly: a more frequent schedule is not
	// honored.
	InstancePruneSchedule string `json:"instancePruneSchedule"`
	// MaxInstancesPerAgent caps the non-prunable instances of one agent. When the cap is
	// reached, a new instance replaces the oldest stale one (not seen within
	// InstanceStaleAfter); only when every counted instance is fresh does a report from a new
	// instance get 409 (and its heartbeats are not recorded). CCF_AGENT_MAX_INSTANCES,
	// default 500.
	MaxInstancesPerAgent int `json:"maxInstancesPerAgent"`
}

// DefaultAgentsConfig returns the defaults.
func DefaultAgentsConfig() *AgentsConfig {
	return &AgentsConfig{
		InstanceStaleAfter:       10 * time.Minute,
		InstanceRetention:        720 * time.Hour,
		OneShotInstanceRetention: 24 * time.Hour,
		InstancePruneEnabled:     true,
		InstancePruneSchedule:    "0 17 * * * *",
		MaxInstancesPerAgent:     500,
	}
}

// LoadAgentsConfig reads the CCF_AGENT_* settings, falling back to the default for any value
// that is unset or not positive.
func LoadAgentsConfig() *AgentsConfig {
	cfg := DefaultAgentsConfig()
	if d := viper.GetDuration("agent_instance_stale_after"); d > 0 {
		cfg.InstanceStaleAfter = d
	}
	if d := viper.GetDuration("agent_instance_retention"); d > 0 {
		cfg.InstanceRetention = d
	}
	if d := viper.GetDuration("agent_instance_oneshot_retention"); d > 0 {
		cfg.OneShotInstanceRetention = d
	}
	if viper.IsSet("agent_instance_prune_enabled") {
		cfg.InstancePruneEnabled = viper.GetBool("agent_instance_prune_enabled")
	}
	if s := viper.GetString("agent_instance_prune_schedule"); s != "" {
		cfg.InstancePruneSchedule = s
	}
	if n := viper.GetInt("agent_max_instances"); n > 0 {
		cfg.MaxInstancesPerAgent = n
	}
	return cfg
}
