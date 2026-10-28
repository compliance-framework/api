package cmd

import (
	"testing"
	"time"

	"github.com/compliance-framework/api/internal/config"
	"github.com/stretchr/testify/require"
)

// The config loaders below read the global viper, which only sees CCF_* environment
// variables that bindEnvironmentVariables binds (it has no AutomaticEnv). This package's
// init has already run bindEnvironmentVariables, and a bound key reads its variable on
// every lookup, so setting the variables here exercises the real binding.
func TestBindEnvironmentVariables_ConfigLoadersReadEnv(t *testing.T) {
	t.Setenv("CCF_EVIDENCE_BATCH_MAX_ITEMS", "250")
	t.Setenv("CCF_EVIDENCE_BATCH_CHUNK_SIZE", "25")
	t.Setenv("CCF_EVIDENCE_BATCH_WORKERS", "8")
	t.Setenv("CCF_EVIDENCE_BATCH_RETENTION", "72h")
	t.Setenv("CCF_EVIDENCE_BATCH_PRUNE_SCHEDULE", "0 5 * * * *")
	t.Setenv("CCF_SSP_SCOPE_AUTO_FILTERS_SCHEDULE", "0 6 * * * *")
	t.Setenv("CCF_SSP_TEMPLATE_DISCOVERY_SCHEDULE", "0 7 * * * *")
	t.Setenv("CCF_SSP_TEMPLATE_STALE_AFTER", "48h")

	batch, err := config.LoadEvidenceBatchConfig()
	require.NoError(t, err)
	require.Equal(t, &config.EvidenceBatchConfig{
		MaxItems:      250,
		ChunkSize:     25,
		Workers:       8,
		Retention:     72 * time.Hour,
		PruneSchedule: "0 5 * * * *",
	}, batch)

	require.Equal(t, &config.SSPScopeConfig{AutoFiltersSchedule: "0 6 * * * *"}, config.LoadSSPScopeConfig())

	template, err := config.LoadSSPTemplateConfig()
	require.NoError(t, err)
	require.Equal(t, &config.SSPTemplateConfig{DiscoverySchedule: "0 7 * * * *", StaleAfter: 48 * time.Hour}, template)
}
