package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
)

// WorkflowConfig contains configuration for the workflow scheduler
type WorkflowConfig struct {
	// SchedulerEnabled determines if the workflow scheduler is enabled
	SchedulerEnabled bool `mapstructure:"scheduler_enabled" yaml:"scheduler_enabled" json:"schedulerEnabled"`

	// Schedule is the cron schedule for the workflow scheduler
	Schedule string `mapstructure:"scheduler_schedule" yaml:"scheduler_schedule" json:"schedulerSchedule"`

	// GracePeriodDays is the number of days before a workflow step is considered overdue
	GracePeriodDays int `mapstructure:"grace_period_days" yaml:"grace_period_days" json:"gracePeriodDays"`

	// OverdueCheckEnabled determines if we should check for overdue workflows
	OverdueCheckEnabled bool `mapstructure:"overdue_check_enabled" yaml:"overdue_check_enabled" json:"overdueCheckEnabled"`
}

// DefaultWorkflowConfig returns a default workflow configuration
func DefaultWorkflowConfig() *WorkflowConfig {
	return &WorkflowConfig{
		SchedulerEnabled:    false,
		Schedule:            "@every 15m",
		GracePeriodDays:     7,
		OverdueCheckEnabled: true,
	}
}

// LoadWorkflowConfig loads workflow configuration from a file or environment variables
func LoadWorkflowConfig(path string) (*WorkflowConfig, error) {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))

	// Set defaults
	v.SetDefault("scheduler_enabled", false)
	v.SetDefault("scheduler_schedule", "@every 15m")
	v.SetDefault("grace_period_days", 7)
	v.SetDefault("overdue_check_enabled", true)

	// Configure environment variable loading
	v.SetEnvPrefix("CCF_WORKFLOW")
	v.SetEnvKeyReplacer(strings.NewReplacer("::", "_", ".", "_", "-", "_"))
	v.AutomaticEnv()

	// Try to load from file if path is provided
	if path != "" {
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return nil, fmt.Errorf("failed to read workflow config file: %w", err)
			}
			// If file not found, we continue with defaults and env vars
		}
	}

	var config WorkflowConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to parse workflow config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

// Validate checks if the configuration is valid
func (c *WorkflowConfig) Validate() error {
	if c.SchedulerEnabled {
		parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
		if _, err := parser.Parse(c.Schedule); err != nil {
			return fmt.Errorf("invalid workflow scheduler schedule: %w", err)
		}
	}
	if c.GracePeriodDays < 0 {
		return fmt.Errorf("workflow grace period days must be non-negative")
	}
	return nil
}
