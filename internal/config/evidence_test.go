package config

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

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
