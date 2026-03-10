package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
)

// RiskConfig contains configuration for risk-related periodic workers.
type RiskConfig struct {
	ReviewDeadlineReminderEnabled  bool   `mapstructure:"review_deadline_reminder_enabled" yaml:"review_deadline_reminder_enabled" json:"reviewDeadlineReminderEnabled"`
	ReviewDeadlineReminderSchedule string `mapstructure:"review_deadline_reminder_schedule" yaml:"review_deadline_reminder_schedule" json:"reviewDeadlineReminderSchedule"`

	ReviewOverdueEscalationEnabled  bool   `mapstructure:"review_overdue_escalation_enabled" yaml:"review_overdue_escalation_enabled" json:"reviewOverdueEscalationEnabled"`
	ReviewOverdueEscalationSchedule string `mapstructure:"review_overdue_escalation_schedule" yaml:"review_overdue_escalation_schedule" json:"reviewOverdueEscalationSchedule"`

	StaleRiskScannerEnabled  bool   `mapstructure:"stale_risk_scanner_enabled" yaml:"stale_risk_scanner_enabled" json:"staleRiskScannerEnabled"`
	StaleRiskScannerSchedule string `mapstructure:"stale_risk_scanner_schedule" yaml:"stale_risk_scanner_schedule" json:"staleRiskScannerSchedule"`

	EvidenceReconciliationEnabled  bool   `mapstructure:"evidence_reconciliation_enabled" yaml:"evidence_reconciliation_enabled" json:"evidenceReconciliationEnabled"`
	EvidenceReconciliationSchedule string `mapstructure:"evidence_reconciliation_schedule" yaml:"evidence_reconciliation_schedule" json:"evidenceReconciliationSchedule"`

	AutoReopenEnabled       bool `mapstructure:"auto_reopen_enabled" yaml:"auto_reopen_enabled" json:"autoReopenEnabled"`
	AutoReopenThresholdDays int  `mapstructure:"auto_reopen_threshold_days" yaml:"auto_reopen_threshold_days" json:"autoReopenThresholdDays"`
}

func DefaultRiskConfig() *RiskConfig {
	return &RiskConfig{
		ReviewDeadlineReminderEnabled:   false,
		ReviewDeadlineReminderSchedule:  "0 0 8 * * *",
		ReviewOverdueEscalationEnabled:  false,
		ReviewOverdueEscalationSchedule: "0 0 9 * * *",
		StaleRiskScannerEnabled:         false,
		StaleRiskScannerSchedule:        "0 0 10 * * 1",
		EvidenceReconciliationEnabled:   false,
		EvidenceReconciliationSchedule:  "0 30 10 * * *",
		AutoReopenEnabled:               false,
		AutoReopenThresholdDays:         30,
	}
}

func LoadRiskConfig(path string) (*RiskConfig, error) {
	v := viper.NewWithOptions(viper.KeyDelimiter("::"))

	def := DefaultRiskConfig()
	v.SetDefault("review_deadline_reminder_enabled", def.ReviewDeadlineReminderEnabled)
	v.SetDefault("review_deadline_reminder_schedule", def.ReviewDeadlineReminderSchedule)
	v.SetDefault("review_overdue_escalation_enabled", def.ReviewOverdueEscalationEnabled)
	v.SetDefault("review_overdue_escalation_schedule", def.ReviewOverdueEscalationSchedule)
	v.SetDefault("stale_risk_scanner_enabled", def.StaleRiskScannerEnabled)
	v.SetDefault("stale_risk_scanner_schedule", def.StaleRiskScannerSchedule)
	v.SetDefault("evidence_reconciliation_enabled", def.EvidenceReconciliationEnabled)
	v.SetDefault("evidence_reconciliation_schedule", def.EvidenceReconciliationSchedule)
	v.SetDefault("auto_reopen_enabled", def.AutoReopenEnabled)
	v.SetDefault("auto_reopen_threshold_days", def.AutoReopenThresholdDays)

	v.SetEnvPrefix("CCF_RISK")
	v.SetEnvKeyReplacer(strings.NewReplacer("::", "_", ".", "_", "-", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) {
				return nil, fmt.Errorf("failed to read risk config file: %w", err)
			}
		}
	}

	var cfg RiskConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse risk config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *RiskConfig) Validate() error {
	parser := cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

	if c.ReviewDeadlineReminderEnabled {
		if _, err := parser.Parse(c.ReviewDeadlineReminderSchedule); err != nil {
			return fmt.Errorf("invalid review_deadline_reminder_schedule: %w", err)
		}
	}
	if c.ReviewOverdueEscalationEnabled {
		if _, err := parser.Parse(c.ReviewOverdueEscalationSchedule); err != nil {
			return fmt.Errorf("invalid review_overdue_escalation_schedule: %w", err)
		}
	}
	if c.StaleRiskScannerEnabled {
		if _, err := parser.Parse(c.StaleRiskScannerSchedule); err != nil {
			return fmt.Errorf("invalid stale_risk_scanner_schedule: %w", err)
		}
	}
	if c.EvidenceReconciliationEnabled {
		if _, err := parser.Parse(c.EvidenceReconciliationSchedule); err != nil {
			return fmt.Errorf("invalid evidence_reconciliation_schedule: %w", err)
		}
	}
	if c.AutoReopenThresholdDays < 0 {
		return fmt.Errorf("risk auto reopen threshold days must be non-negative")
	}

	return nil
}
