package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestLoadEvidenceBadgeMaxParams(t *testing.T) {
	for _, tt := range []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "default", want: 3},
		{name: "custom", value: "5", want: 5},
		{name: "one", value: "1", want: 1},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "fraction", value: "1.5", wantErr: true},
		{name: "not an integer", value: "unlimited", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			if tt.value != "" {
				v.Set("evidence_badge_max_params", tt.value)
			}
			value, err := LoadEvidenceBadgeMaxParamsFromViper(v)
			if tt.wantErr {
				require.ErrorContains(t, err, "CCF_EVIDENCE_BADGE_MAX_PARAMS")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, value)
		})
	}
	t.Run("environment override", func(t *testing.T) {
		t.Setenv("CCF_EVIDENCE_BADGE_MAX_PARAMS", "7")
		v := viper.New()
		v.SetEnvPrefix("CCF")
		v.AutomaticEnv()
		value, err := LoadEvidenceBadgeMaxParamsFromViper(v)
		require.NoError(t, err)
		require.Equal(t, 7, value)
	})
}

func TestLoadEvidenceSubjectConfigDefaults(t *testing.T) {
	cfg, err := LoadEvidenceSubjectConfigFromViper(viper.New())

	require.NoError(t, err)
	require.Equal(t, EvidenceRequireSubjectOff, cfg.RequireSubject)
	require.False(t, cfg.ManualRequireSubject)
}

func TestLoadEvidenceSubjectConfigReadsFlags(t *testing.T) {
	v := viper.New()
	v.Set("evidence_require_subject", " Enforce ")
	v.Set("manual_evidence_require_subject", "true")

	cfg, err := LoadEvidenceSubjectConfigFromViper(v)

	require.NoError(t, err)
	require.Equal(t, EvidenceRequireSubjectEnforce, cfg.RequireSubject)
	require.True(t, cfg.ManualRequireSubject)
}

func TestLoadEvidenceSubjectConfigRejectsUnknownMode(t *testing.T) {
	v := viper.New()
	v.Set("evidence_require_subject", "strict")

	cfg, err := LoadEvidenceSubjectConfigFromViper(v)

	require.Nil(t, cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CCF_EVIDENCE_REQUIRE_SUBJECT")
}

func TestLoadEvidenceBatchConfigDefaults(t *testing.T) {
	cfg, err := LoadEvidenceBatchConfigFromViper(viper.New())

	require.NoError(t, err)
	require.Equal(t, &EvidenceBatchConfig{
		MaxItems:      DefaultEvidenceBatchMaxItems,
		ChunkSize:     DefaultEvidenceBatchChunkSize,
		Workers:       DefaultEvidenceBatchWorkers,
		Retention:     DefaultEvidenceBatchRetention,
		PruneSchedule: DefaultEvidenceBatchPruneSchedule,
	}, cfg)
}

func TestLoadEvidenceBatchConfigReadsSettings(t *testing.T) {
	v := viper.New()
	v.Set("evidence_batch_max_items", "5000")
	v.Set("evidence_batch_chunk_size", "250")
	v.Set("evidence_batch_workers", "8")
	v.Set("evidence_batch_retention", "72h")
	v.Set("evidence_batch_prune_schedule", "0 0 * * * *")

	cfg, err := LoadEvidenceBatchConfigFromViper(v)

	require.NoError(t, err)
	require.Equal(t, &EvidenceBatchConfig{MaxItems: 5000, ChunkSize: 250, Workers: 8, Retention: 72 * time.Hour, PruneSchedule: "0 0 * * * *"}, cfg)
}

func TestLoadEvidenceBatchConfigRejectsNonPositive(t *testing.T) {
	for _, key := range []string{"evidence_batch_max_items", "evidence_batch_chunk_size", "evidence_batch_workers"} {
		t.Run(key, func(t *testing.T) {
			v := viper.New()
			v.Set(key, "0")

			cfg, err := LoadEvidenceBatchConfigFromViper(v)

			require.Nil(t, cfg)
			require.Error(t, err)
			require.Contains(t, err.Error(), "CCF_EVIDENCE_BATCH_")
		})
	}
}

func TestLoadEvidenceBatchConfigRejectsBadRetention(t *testing.T) {
	for _, value := range []string{"0s", "-1h", "a week"} {
		t.Run(value, func(t *testing.T) {
			v := viper.New()
			v.Set("evidence_batch_retention", value)

			cfg, err := LoadEvidenceBatchConfigFromViper(v)

			require.Nil(t, cfg)
			require.ErrorContains(t, err, "CCF_EVIDENCE_BATCH_RETENTION")
		})
	}
}
