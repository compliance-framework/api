package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultWorkflowConfig(t *testing.T) {
	config := DefaultWorkflowConfig()
	assert.False(t, config.SchedulerEnabled)
	assert.Equal(t, "@every 15m", config.Schedule)
	assert.Equal(t, 7, config.GracePeriodDays)
	assert.True(t, config.OverdueCheckEnabled)
	assert.False(t, config.DueSoonEnabled)
	assert.Equal(t, "0 0 8 * * *", config.DueSoonSchedule)
	assert.False(t, config.TaskDigestEnabled)
	assert.Equal(t, "0 0 8 * * *", config.TaskDigestSchedule)
}

func TestLoadWorkflowConfig_Defaults(t *testing.T) {
	// Ensure no env vars interfere
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_SCHEDULER_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_SCHEDULER_SCHEDULE"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_GRACE_PERIOD_DAYS"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_OVERDUE_CHECK_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_DUE_SOON_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_DUE_SOON_SCHEDULE"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_TASK_DIGEST_ENABLED"))
	require.NoError(t, os.Unsetenv("CCF_WORKFLOW_TASK_DIGEST_SCHEDULE"))

	config, err := LoadWorkflowConfig("")
	require.NoError(t, err)

	assert.False(t, config.SchedulerEnabled)
	assert.Equal(t, "@every 15m", config.Schedule)
	assert.Equal(t, 7, config.GracePeriodDays)
	assert.True(t, config.OverdueCheckEnabled)
	assert.False(t, config.DueSoonEnabled)
	assert.Equal(t, "0 0 8 * * *", config.DueSoonSchedule)
	assert.False(t, config.TaskDigestEnabled)
	assert.Equal(t, "0 0 8 * * *", config.TaskDigestSchedule)
}

func TestLoadWorkflowConfig_EnvVars(t *testing.T) {
	require.NoError(t, os.Setenv("CCF_WORKFLOW_SCHEDULER_ENABLED", "true"))
	require.NoError(t, os.Setenv("CCF_WORKFLOW_SCHEDULER_SCHEDULE", "@hourly"))
	require.NoError(t, os.Setenv("CCF_WORKFLOW_GRACE_PERIOD_DAYS", "14"))
	require.NoError(t, os.Setenv("CCF_WORKFLOW_OVERDUE_CHECK_ENABLED", "false"))
	defer func() {
		_ = os.Unsetenv("CCF_WORKFLOW_SCHEDULER_ENABLED")
		_ = os.Unsetenv("CCF_WORKFLOW_SCHEDULER_SCHEDULE")
		_ = os.Unsetenv("CCF_WORKFLOW_GRACE_PERIOD_DAYS")
		_ = os.Unsetenv("CCF_WORKFLOW_OVERDUE_CHECK_ENABLED")
	}()

	config, err := LoadWorkflowConfig("")
	require.NoError(t, err)

	assert.True(t, config.SchedulerEnabled)
	assert.Equal(t, "@hourly", config.Schedule)
	assert.Equal(t, 14, config.GracePeriodDays)
	assert.False(t, config.OverdueCheckEnabled)
}

func TestLoadWorkflowConfig_NotificationEnvVars(t *testing.T) {
	require.NoError(t, os.Setenv("CCF_WORKFLOW_DUE_SOON_ENABLED", "true"))
	require.NoError(t, os.Setenv("CCF_WORKFLOW_DUE_SOON_SCHEDULE", "0 0 9 * * *"))
	require.NoError(t, os.Setenv("CCF_WORKFLOW_TASK_DIGEST_ENABLED", "true"))
	require.NoError(t, os.Setenv("CCF_WORKFLOW_TASK_DIGEST_SCHEDULE", "0 0 7 * * *"))
	defer func() {
		_ = os.Unsetenv("CCF_WORKFLOW_DUE_SOON_ENABLED")
		_ = os.Unsetenv("CCF_WORKFLOW_DUE_SOON_SCHEDULE")
		_ = os.Unsetenv("CCF_WORKFLOW_TASK_DIGEST_ENABLED")
		_ = os.Unsetenv("CCF_WORKFLOW_TASK_DIGEST_SCHEDULE")
	}()

	config, err := LoadWorkflowConfig("")
	require.NoError(t, err)

	assert.True(t, config.DueSoonEnabled)
	assert.Equal(t, "0 0 9 * * *", config.DueSoonSchedule)
	assert.True(t, config.TaskDigestEnabled)
	assert.Equal(t, "0 0 7 * * *", config.TaskDigestSchedule)
}

func TestLoadWorkflowConfig_File(t *testing.T) {
	content := `
scheduler_enabled: true
scheduler_schedule: "@daily"
grace_period_days: 30
overdue_check_enabled: false
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "workflow.yaml")
	err := os.WriteFile(configPath, []byte(content), 0644)
	require.NoError(t, err)

	config, err := LoadWorkflowConfig(configPath)
	require.NoError(t, err)

	assert.True(t, config.SchedulerEnabled)
	assert.Equal(t, "@daily", config.Schedule)
	assert.Equal(t, 30, config.GracePeriodDays)
	assert.False(t, config.OverdueCheckEnabled)
}

func TestLoadWorkflowConfig_MissingFileUsesDefaults(t *testing.T) {
	config, err := LoadWorkflowConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.NoError(t, err)

	def := DefaultWorkflowConfig()
	assert.Equal(t, def.SchedulerEnabled, config.SchedulerEnabled)
	assert.Equal(t, def.Schedule, config.Schedule)
	assert.Equal(t, def.GracePeriodDays, config.GracePeriodDays)
}

func TestWorkflowConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *WorkflowConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &WorkflowConfig{
				SchedulerEnabled: true,
				Schedule:         "@every 15m",
				GracePeriodDays:  7,
			},
			wantErr: false,
		},
		{
			name: "invalid schedule",
			config: &WorkflowConfig{
				SchedulerEnabled: true,
				Schedule:         "invalid-cron",
				GracePeriodDays:  7,
			},
			wantErr: true,
		},
		{
			name: "negative grace period",
			config: &WorkflowConfig{
				SchedulerEnabled: true,
				Schedule:         "@every 15m",
				GracePeriodDays:  -1,
			},
			wantErr: true,
		},
		{
			name: "scheduler disabled with invalid schedule (should pass as validation is skipped for schedule)",
			config: &WorkflowConfig{
				SchedulerEnabled: false,
				Schedule:         "invalid-cron", // Schedule validation skipped if disabled?
				// Actually Validate implementation checks: if c.SchedulerEnabled { ... }
				GracePeriodDays: 7,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
