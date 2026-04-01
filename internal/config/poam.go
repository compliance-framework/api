package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
)

// PoamConfig contains configuration for POAM-related periodic workers.
// All three jobs are disabled by default; enable via environment variables
// or a poam.yaml config file (CCF_POAM_CONFIG env var).
type PoamConfig struct {
	// DeadlineReminderEnabled enables the daily POAM deadline reminder scanner (0 8 * * *).
	DeadlineReminderEnabled  bool   `mapstructure:"deadline_reminder_enabled"  yaml:"deadline_reminder_enabled"  json:"deadlineReminderEnabled"`
	DeadlineReminderSchedule string `mapstructure:"deadline_reminder_schedule" yaml:"deadline_reminder_schedule" json:"deadlineReminderSchedule"`
	// ReminderWindowDays is the look-ahead window (in days) for the deadline reminder.
	// Items with deadline - now <= ReminderWindowDays are included. Default: 30.
	ReminderWindowDays int `mapstructure:"reminder_window_days" yaml:"reminder_window_days" json:"reminderWindowDays"`

	// OverdueTransitionEnabled enables the daily overdue transition scanner (0 9 * * *).
	OverdueTransitionEnabled  bool   `mapstructure:"overdue_transition_enabled"  yaml:"overdue_transition_enabled"  json:"overdueTransitionEnabled"`
	OverdueTransitionSchedule string `mapstructure:"overdue_transition_schedule" yaml:"overdue_transition_schedule" json:"overdueTransitionSchedule"`

	// MilestoneOverdueEnabled enables the weekly incomplete milestone scanner (0 10 * * 1).
	MilestoneOverdueEnabled  bool   `mapstructure:"milestone_overdue_enabled"  yaml:"milestone_overdue_enabled"  json:"milestoneOverdueEnabled"`
	MilestoneOverdueSchedule string `mapstructure:"milestone_overdue_schedule" yaml:"milestone_overdue_schedule" json:"milestoneOverdueSchedule"`

	// OpenDigestEnabled enables the daily POAM open digest job (0 0 7 * * *).
	OpenDigestEnabled  bool   `mapstructure:"open_digest_enabled"  yaml:"open_digest_enabled"  json:"openDigestEnabled"`
	OpenDigestSchedule string `mapstructure:"open_digest_schedule" yaml:"open_digest_schedule" json:"openDigestSchedule"`
	// OpenDigestWindow controls whether the digest covers a "daily" or "weekly" window.
	OpenDigestWindow string `mapstructure:"open_digest_window"   yaml:"open_digest_window"   json:"openDigestWindow"`

	// WebBaseURL is the base URL prepended to POAM deep-links in notification emails.
	WebBaseURL string `mapstructure:"web_base_url" yaml:"web_base_url" json:"webBaseURL"`
}

// DefaultPoamConfig returns a PoamConfig with safe defaults (all jobs disabled).
func DefaultPoamConfig() *PoamConfig {
	return &PoamConfig{
		DeadlineReminderEnabled:   false,
		DeadlineReminderSchedule:  "0 0 8 * * *",
		ReminderWindowDays:        30,
		OverdueTransitionEnabled:  false,
		OverdueTransitionSchedule: "0 0 9 * * *",
		MilestoneOverdueEnabled:   false,
		MilestoneOverdueSchedule:  "0 0 10 * * 1",
		OpenDigestEnabled:         false,
		OpenDigestSchedule:        "0 0 7 * * *",
		OpenDigestWindow:          "daily",
		WebBaseURL:                "",
	}
}

// LoadPoamConfig loads PoamConfig from a YAML file and/or CCF_POAM_* env vars.
// If path is empty or the file does not exist, defaults are used.
func LoadPoamConfig(path string) (*PoamConfig, error) {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))
	def := DefaultPoamConfig()

	v.SetDefault("deadline_reminder_enabled", def.DeadlineReminderEnabled)
	v.SetDefault("deadline_reminder_schedule", def.DeadlineReminderSchedule)
	v.SetDefault("reminder_window_days", def.ReminderWindowDays)
	v.SetDefault("overdue_transition_enabled", def.OverdueTransitionEnabled)
	v.SetDefault("overdue_transition_schedule", def.OverdueTransitionSchedule)
	v.SetDefault("milestone_overdue_enabled", def.MilestoneOverdueEnabled)
	v.SetDefault("milestone_overdue_schedule", def.MilestoneOverdueSchedule)
	v.SetDefault("open_digest_enabled", def.OpenDigestEnabled)
	v.SetDefault("open_digest_schedule", def.OpenDigestSchedule)
	v.SetDefault("open_digest_window", def.OpenDigestWindow)
	v.SetDefault("web_base_url", def.WebBaseURL)

	v.SetEnvPrefix("CCF_POAM")
	v.SetEnvKeyReplacer(strings.NewReplacer("::", "_", ".", "_", "-", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("failed to read poam config file %q: %w", path, err)
			}
			// File not found — fall through to defaults + env vars.
		}
	}

	var cfg PoamConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal poam config: %w", err)
	}
	return &cfg, nil
}

// Validate checks that all enabled jobs have valid cron schedules.
func (c *PoamConfig) Validate() error {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	type check struct {
		enabled  bool
		schedule string
		name     string
	}
	checks := []check{
		{c.DeadlineReminderEnabled, c.DeadlineReminderSchedule, "deadline_reminder_schedule"},
		{c.OverdueTransitionEnabled, c.OverdueTransitionSchedule, "overdue_transition_schedule"},
		{c.MilestoneOverdueEnabled, c.MilestoneOverdueSchedule, "milestone_overdue_schedule"},
		{c.OpenDigestEnabled, c.OpenDigestSchedule, "open_digest_schedule"},
	}
	for _, ch := range checks {
		if ch.enabled {
			if _, err := parser.Parse(ch.schedule); err != nil {
				return fmt.Errorf("invalid cron schedule for %s %q: %w", ch.name, ch.schedule, err)
			}
		}
	}
	return nil
}
