package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	AIProviderAnthropic = "anthropic"
	DefaultAIModel      = "claude-opus-4-8"
)

type AIConfig struct {
	Enabled              bool          `mapstructure:"enabled" json:"enabled"`
	Provider             string        `mapstructure:"provider" json:"provider"`
	APIKey               string        `mapstructure:"api_key" json:"-" yaml:"-"`
	Model                string        `mapstructure:"model" json:"model"`
	BaseURL              string        `mapstructure:"base_url" json:"baseUrl"`
	RequestTimeout       time.Duration `mapstructure:"request_timeout" json:"requestTimeout"`
	MaxControlsPerChunk  int           `mapstructure:"max_controls_per_chunk" json:"maxControlsPerChunk"`
	MaxLabelSetsPerChunk int           `mapstructure:"max_label_sets_per_chunk" json:"maxLabelSetsPerChunk"`
	QueueWorkers         int           `mapstructure:"queue_workers" json:"queueWorkers"`
	MaxCallsPerRun       int           `mapstructure:"max_calls_per_run" json:"maxCallsPerRun"`
	MaxSuggestionsPerRun int           `mapstructure:"max_suggestions_per_run" json:"maxSuggestionsPerRun"`
}

func DefaultAIConfig() *AIConfig {
	return &AIConfig{
		Enabled:              false,
		Provider:             AIProviderAnthropic,
		Model:                DefaultAIModel,
		RequestTimeout:       120 * time.Second,
		MaxControlsPerChunk:  40,
		MaxLabelSetsPerChunk: 200,
		QueueWorkers:         4,
		MaxCallsPerRun:       0,
		MaxSuggestionsPerRun: 500,
	}
}

func LoadAIConfigFromViper(v *viper.Viper) (*AIConfig, error) {
	cfg := &AIConfig{
		Enabled:              v.GetBool("ai_enabled"),
		Provider:             strings.ToLower(strings.TrimSpace(stripQuotes(v.GetString("ai_provider")))),
		APIKey:               stripQuotes(v.GetString("ai_api_key")),
		Model:                stripQuotes(v.GetString("ai_model")),
		BaseURL:              stripQuotes(v.GetString("ai_base_url")),
		RequestTimeout:       v.GetDuration("ai_request_timeout"),
		MaxControlsPerChunk:  v.GetInt("ai_max_controls_per_chunk"),
		MaxLabelSetsPerChunk: v.GetInt("ai_max_label_sets_per_chunk"),
		QueueWorkers:         v.GetInt("ai_queue_workers"),
		MaxCallsPerRun:       v.GetInt("ai_max_calls_per_run"),
		MaxSuggestionsPerRun: v.GetInt("ai_max_suggestions_per_run"),
	}

	def := DefaultAIConfig()
	if cfg.Provider == "" {
		cfg.Provider = def.Provider
	}
	if cfg.Model == "" {
		cfg.Model = def.Model
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = def.RequestTimeout
	}
	if cfg.MaxControlsPerChunk == 0 {
		cfg.MaxControlsPerChunk = def.MaxControlsPerChunk
	}
	if cfg.MaxLabelSetsPerChunk == 0 {
		cfg.MaxLabelSetsPerChunk = def.MaxLabelSetsPerChunk
	}
	if cfg.QueueWorkers == 0 {
		cfg.QueueWorkers = def.QueueWorkers
	}
	if cfg.MaxSuggestionsPerRun == 0 {
		cfg.MaxSuggestionsPerRun = def.MaxSuggestionsPerRun
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func LoadAIConfig() (*AIConfig, error) {
	return LoadAIConfigFromViper(viper.GetViper())
}

func (c *AIConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	switch strings.ToLower(strings.TrimSpace(c.Provider)) {
	case AIProviderAnthropic:
		c.Provider = AIProviderAnthropic
		return nil
	default:
		return fmt.Errorf("CCF_AI_PROVIDER must be %q", AIProviderAnthropic)
	}
}

func (c AIConfig) String() string {
	apiKey := ""
	if c.APIKey != "" {
		apiKey = "<redacted>"
	}
	return fmt.Sprintf(
		"{Enabled:%t Provider:%q APIKey:%s Model:%q BaseURL:%q RequestTimeout:%s MaxControlsPerChunk:%d MaxLabelSetsPerChunk:%d QueueWorkers:%d MaxCallsPerRun:%d MaxSuggestionsPerRun:%d}",
		c.Enabled,
		c.Provider,
		apiKey,
		c.Model,
		c.BaseURL,
		c.RequestTimeout,
		c.MaxControlsPerChunk,
		c.MaxLabelSetsPerChunk,
		c.QueueWorkers,
		c.MaxCallsPerRun,
		c.MaxSuggestionsPerRun,
	)
}

func (c AIConfig) GoString() string {
	return c.String()
}
