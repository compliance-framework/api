package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultRiskConfig(t *testing.T) {
	cfg := DefaultRiskConfig()
	assert.False(t, cfg.ReviewDeadlineReminderEnabled)
	assert.Equal(t, "0 0 8 * * *", cfg.ReviewDeadlineReminderSchedule)
	assert.False(t, cfg.ReviewOverdueEscalationEnabled)
	assert.Equal(t, "0 0 9 * * *", cfg.ReviewOverdueEscalationSchedule)
	assert.False(t, cfg.StaleRiskScannerEnabled)
	assert.Equal(t, "0 0 10 * * 1", cfg.StaleRiskScannerSchedule)
	assert.False(t, cfg.EvidenceReconciliationEnabled)
	assert.Equal(t, "0 30 10 * * *", cfg.EvidenceReconciliationSchedule)
	assert.False(t, cfg.AutoReopenEnabled)
	assert.Equal(t, 30, cfg.AutoReopenThresholdDays)
}

func TestLoadRiskConfigDefaults(t *testing.T) {
	require.NoError(t, os.Unsetenv("CCF_RISK_REVIEW_DEADLINE_REMINDER_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_RISK_REVIEW_DEADLINE_REMINDER_SCHEDULE"))
	require.NoError(t, os.Unsetenv("CCF_RISK_REVIEW_OVERDUE_ESCALATION_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_RISK_REVIEW_OVERDUE_ESCALATION_SCHEDULE"))
	require.NoError(t, os.Unsetenv("CCF_RISK_STALE_RISK_SCANNER_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_RISK_STALE_RISK_SCANNER_SCHEDULE"))
	require.NoError(t, os.Unsetenv("CCF_RISK_EVIDENCE_RECONCILIATION_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_RISK_EVIDENCE_RECONCILIATION_SCHEDULE"))
	require.NoError(t, os.Unsetenv("CCF_RISK_AUTO_REOPEN_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_RISK_AUTO_REOPEN_THRESHOLD_DAYS"))

	cfg, err := LoadRiskConfig("")
	require.NoError(t, err)
	assert.False(t, cfg.ReviewDeadlineReminderEnabled)
	assert.False(t, cfg.ReviewOverdueEscalationEnabled)
	assert.False(t, cfg.StaleRiskScannerEnabled)
	assert.False(t, cfg.EvidenceReconciliationEnabled)
	assert.False(t, cfg.AutoReopenEnabled)
	assert.Equal(t, 30, cfg.AutoReopenThresholdDays)
}

func TestLoadRiskConfigFromEnv(t *testing.T) {
	require.NoError(t, os.Setenv("CCF_RISK_REVIEW_DEADLINE_REMINDER_ENABLED", "true"))
	require.NoError(t, os.Setenv("CCF_RISK_REVIEW_DEADLINE_REMINDER_SCHEDULE", "0 15 8 * * *"))
	require.NoError(t, os.Setenv("CCF_RISK_AUTO_REOPEN_ENABLED", "true"))
	require.NoError(t, os.Setenv("CCF_RISK_AUTO_REOPEN_THRESHOLD_DAYS", "45"))
	defer func() {
		_ = os.Unsetenv("CCF_RISK_REVIEW_DEADLINE_REMINDER_ENABLED")
		_ = os.Unsetenv("CCF_RISK_REVIEW_DEADLINE_REMINDER_SCHEDULE")
		_ = os.Unsetenv("CCF_RISK_AUTO_REOPEN_ENABLED")
		_ = os.Unsetenv("CCF_RISK_AUTO_REOPEN_THRESHOLD_DAYS")
	}()

	cfg, err := LoadRiskConfig("")
	require.NoError(t, err)
	assert.True(t, cfg.ReviewDeadlineReminderEnabled)
	assert.Equal(t, "0 15 8 * * *", cfg.ReviewDeadlineReminderSchedule)
	assert.True(t, cfg.AutoReopenEnabled)
	assert.Equal(t, 45, cfg.AutoReopenThresholdDays)
}

func TestLoadRiskConfigFromFile(t *testing.T) {
	content := `
review_deadline_reminder_enabled: true
review_deadline_reminder_schedule: "0 0 8 * * *"
review_overdue_escalation_enabled: true
review_overdue_escalation_schedule: "0 0 9 * * *"
stale_risk_scanner_enabled: true
stale_risk_scanner_schedule: "0 0 10 * * 1"
evidence_reconciliation_enabled: true
evidence_reconciliation_schedule: "0 30 10 * * *"
auto_reopen_enabled: true
auto_reopen_threshold_days: 60
`
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "risk.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0644))

	cfg, err := LoadRiskConfig(cfgPath)
	require.NoError(t, err)
	assert.True(t, cfg.ReviewDeadlineReminderEnabled)
	assert.True(t, cfg.ReviewOverdueEscalationEnabled)
	assert.True(t, cfg.StaleRiskScannerEnabled)
	assert.True(t, cfg.EvidenceReconciliationEnabled)
	assert.True(t, cfg.AutoReopenEnabled)
	assert.Equal(t, 60, cfg.AutoReopenThresholdDays)
}

func TestLoadRiskConfigMissingFileUsesDefaults(t *testing.T) {
	cfg, err := LoadRiskConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.NoError(t, err)

	def := DefaultRiskConfig()
	assert.Equal(t, def.ReviewDeadlineReminderEnabled, cfg.ReviewDeadlineReminderEnabled)
	assert.Equal(t, def.ReviewDeadlineReminderSchedule, cfg.ReviewDeadlineReminderSchedule)
	assert.Equal(t, def.AutoReopenThresholdDays, cfg.AutoReopenThresholdDays)
}

func TestRiskConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *RiskConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &RiskConfig{
				ReviewDeadlineReminderEnabled:  true,
				ReviewDeadlineReminderSchedule: "0 0 8 * * *",
				AutoReopenThresholdDays:        30,
			},
			wantErr: false,
		},
		{
			name: "invalid reminder schedule",
			cfg: &RiskConfig{
				ReviewDeadlineReminderEnabled:  true,
				ReviewDeadlineReminderSchedule: "not-cron",
			},
			wantErr: true,
		},
		{
			name: "negative threshold",
			cfg: &RiskConfig{
				AutoReopenThresholdDays: -1,
			},
			wantErr: true,
		},
		{
			name: "disabled schedule may be invalid",
			cfg: &RiskConfig{
				ReviewDeadlineReminderEnabled:  false,
				ReviewDeadlineReminderSchedule: "not-cron",
				AutoReopenThresholdDays:        0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
