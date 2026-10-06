package handler

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxStoredRemoteConfigBytes is the most remote-config JSON a stored report may keep. The
// block is a summary column returned for every instance on a page of the instance list.
const maxStoredRemoteConfigBytes = 64 << 10

func regressionReport(rc *agentconfig.RemoteConfig) agentconfig.Report {
	return agentconfig.Report{
		Mode:            agentconfig.ModeApplySafe,
		Status:          agentconfig.StatusApplied,
		Base:            json.RawMessage(`{}`),
		Effective:       json.RawMessage(`{}`),
		EffectiveDigest: "sha256:" + strings.Repeat("a", 64),
		RemoteConfig:    rc,
	}
}

// Regression (review #480/#476, fp 72f95c2fcf2d): normalizeReport must bound remote-config,
// like warnings, unsafe changes and plugins, and mark the report truncated when it cuts it.
func TestNormalizeReportBoundsRemoteConfig(t *testing.T) {
	sources := make([]string, 100_000)
	flags := make([]string, 100_000)
	for i := range sources {
		sources[i] = "ghcr.io/acme/" + strings.Repeat("a", 20)
		flags[i] = "plugin:" + strings.Repeat("k", 20)
	}
	r := regressionReport(&agentconfig.RemoteConfig{
		Mode:                   agentconfig.ModeApplySafe,
		PollInterval:           strings.Repeat("p", 500_000),
		TrustedSources:         sources,
		OverridableConfigFlags: flags,
	})
	_, err := normalizeReport(&r)
	require.NoError(t, err)
	raw, err := json.Marshal(r.RemoteConfig)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(raw), maxStoredRemoteConfigBytes, "remote-config is stored and listed for every instance")
	assert.True(t, r.Truncated)
}

// A normal remote-config block is stored as sent.
func TestNormalizeReportKeepsSmallRemoteConfig(t *testing.T) {
	rc := &agentconfig.RemoteConfig{
		Mode:                   agentconfig.ModeApplySafe,
		PollInterval:           "60s",
		TrustedSources:         []string{"ghcr.io/compliance-framework/*"},
		OverridableConfigFlags: []string{"ssh:port"},
	}
	r := regressionReport(rc)
	_, err := normalizeReport(&r)
	require.NoError(t, err)
	assert.False(t, r.Truncated)
	assert.Equal(t, []string{"ghcr.io/compliance-framework/*"}, r.RemoteConfig.TrustedSources)
	assert.Equal(t, []string{"ssh:port"}, r.RemoteConfig.OverridableConfigFlags)
	assert.Equal(t, "60s", r.RemoteConfig.PollInterval)
}

// The bound holds for the worst-case escaping (each '<' encodes to 6 bytes) at every cap, and
// an entry over the length cap is dropped, never cut into a broader pattern.
func TestNormalizeReportRemoteConfigWorstCaseEscaping(t *testing.T) {
	escaped := strings.Repeat("<", (maxReportRemoteEntryBytes-2)/6) // just within the cap once encoded
	entries := make([]string, maxReportRemoteListEntries)
	for i := range entries {
		entries[i] = escaped
	}
	r := regressionReport(&agentconfig.RemoteConfig{
		Mode:                   strings.Repeat("<", maxReportRemoteModeLen),
		PollInterval:           strings.Repeat("<", maxReportRemotePollIntervalLen),
		TrustedSources:         entries,
		OverridableConfigFlags: slices.Clone(entries),
	})
	_, err := normalizeReport(&r)
	require.NoError(t, err)
	raw, err := json.Marshal(r.RemoteConfig)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(raw), maxStoredRemoteConfigBytes)
	assert.False(t, r.Truncated, "every entry is within the caps")
	assert.Len(t, r.RemoteConfig.TrustedSources, maxReportRemoteListEntries)

	long := "ghcr.io/acme/*/" + strings.Repeat("x", maxReportRemoteEntryBytes)
	r = regressionReport(&agentconfig.RemoteConfig{
		TrustedSources:         []string{"ghcr.io/ok/*", long},
		OverridableConfigFlags: []string{long, "ssh:port"},
	})
	_, err = normalizeReport(&r)
	require.NoError(t, err)
	assert.True(t, r.Truncated)
	assert.Equal(t, []string{"ghcr.io/ok/*"}, r.RemoteConfig.TrustedSources)
	assert.Equal(t, []string{"ssh:port"}, r.RemoteConfig.OverridableConfigFlags)
}
