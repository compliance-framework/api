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
	// MaxOutputTokens caps the model's response length per cell. Too low a value
	// truncates the JSON (surfacing as "truncated non-json text content").
	MaxOutputTokens int `mapstructure:"max_output_tokens" json:"maxOutputTokens"`
	// GeneralizableLabelKeys are the label keys whose value identifies an
	// instance/provider rather than the evidence meaning. The deterministic
	// filter-merge detector may drop exactly one of these to generalize several
	// near-duplicate filters into one. Meaning-bearing keys (_policy, type) are
	// never dropped, so they must not appear here.
	GeneralizableLabelKeys []string `mapstructure:"generalizable_label_keys" json:"generalizableLabelKeys"`
	// GeneralizationMinSharedControls is the minimum number of controls the
	// candidate filters must have in common before a merge is proposed, so a
	// merge only fires when it is the same control intent across instances.
	GeneralizationMinSharedControls int `mapstructure:"generalization_min_shared_controls" json:"generalizationMinSharedControls"`
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
		MaxOutputTokens:      8192,
		GeneralizableLabelKeys: []string{
			"provider", "region", "account", "repository", "organization",
			"environment", "host", "namespace", "project", "cluster",
		},
		GeneralizationMinSharedControls: 1,
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
		MaxOutputTokens:      v.GetInt("ai_max_output_tokens"),
		GeneralizableLabelKeys: v.GetStringSlice("ai_generalizable_label_keys"),
		GeneralizationMinSharedControls: v.GetInt("ai_generalization_min_shared_controls"),
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
	if cfg.MaxOutputTokens == 0 {
		cfg.MaxOutputTokens = def.MaxOutputTokens
	}
	if len(cfg.GeneralizableLabelKeys) == 0 {
		cfg.GeneralizableLabelKeys = def.GeneralizableLabelKeys
	}
	if cfg.GeneralizationMinSharedControls <= 0 {
		cfg.GeneralizationMinSharedControls = def.GeneralizationMinSharedControls
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
