package agentconfig

import (
	"regexp"
	"strings"
	"time"
)

// Apply modes (remote_config.mode).
const (
	ModeOff       = "off"
	ModeReport    = "report"
	ModeApplySafe = "apply_safe"
	ModeApplyAll  = "apply_all"
)

const (
	// MaskedValue replaces redacted values. It is exactly this string (R25) and the API
	// rejects it on write, so a redacted view can never round-trip into an overlay.
	MaskedValue = "••••"

	// MaxOverlayBytes bounds the compact JSON of an overlay.
	MaxOverlayBytes = 256 << 10
	// MaxReportBytes bounds a config report body.
	MaxReportBytes = 4 << 20

	// DefaultPollInterval is the remote_config.poll_interval default.
	DefaultPollInterval = 60 * time.Second
	// MinPollInterval is the smallest accepted remote_config.poll_interval.
	MinPollInterval = 15 * time.Second
)

// LockedKeys are the top-level keys an overlay may never set (D3). They always come from the
// agent's local config.
var LockedKeys = []string{"api", "daemon", "remote_config"}

// PluginNamePattern is the name pattern for plugins introduced by an overlay (R28). Viper
// lowercases file plugin names, so upper case would silently create a second plugin.
var PluginNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Config is the declared form of the agent configuration (file, overlay and effective).
// The agent keeps its private runtime structs and converts once from this form (R4).
type Config struct {
	Daemon        bool               `json:"daemon" mapstructure:"daemon"`
	Verbosity     int32              `json:"verbosity" mapstructure:"verbosity"` // 0/1/2 = Info/Debug/Trace
	API           *APIConfig         `json:"api,omitempty" mapstructure:"api"`
	RemoteConfig  *RemoteConfig      `json:"remote_config,omitempty" mapstructure:"remote_config"`
	Plugins       map[string]*Plugin `json:"plugins" mapstructure:"plugins"`
	AgentEvidence *EvidenceConfig    `json:"agent_evidence,omitempty" mapstructure:"agent_evidence"`
}

// APIConfig is the agent's API connection block. It is a locked key.
type APIConfig struct {
	URL  string   `json:"url" mapstructure:"url"`
	Auth *APIAuth `json:"auth,omitempty" mapstructure:"auth"`
}

// APIAuth holds the agent service-account credentials.
type APIAuth struct {
	ClientID     string `json:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret,omitempty" mapstructure:"client_secret"`
}

// HasAuth reports whether both client_id and client_secret are set (non-blank).
func (a *APIConfig) HasAuth() bool {
	return a != nil && a.Auth != nil &&
		strings.TrimSpace(a.Auth.ClientID) != "" &&
		strings.TrimSpace(a.Auth.ClientSecret) != ""
}

// HasPartialAuth reports whether exactly one of client_id and client_secret is set.
func (a *APIConfig) HasPartialAuth() bool {
	if a == nil || a.Auth == nil {
		return false
	}
	return (strings.TrimSpace(a.Auth.ClientID) == "") != (strings.TrimSpace(a.Auth.ClientSecret) == "")
}

// RemoteConfig is the agent's remote-configuration policy. It is set locally only (file,
// host env, CLI), never remotely (R30).
type RemoteConfig struct {
	Mode                   string   `json:"mode,omitempty" mapstructure:"mode"`
	PollInterval           string   `json:"poll_interval,omitempty" mapstructure:"poll_interval"`
	TrustedSources         []string `json:"trusted_sources" mapstructure:"trusted_sources"`                   // default []
	OverridableConfigFlags []string `json:"overridable_config_flags" mapstructure:"overridable_config_flags"` // default []
	AllowLocalSources      bool     `json:"allow_local_sources" mapstructure:"allow_local_sources"`           // default false
}

// EvidenceConfig controls the agent's own evidence.
type EvidenceConfig struct {
	Enabled             *bool  `json:"enabled,omitempty" mapstructure:"enabled"`
	EmitOnRunCompletion *bool  `json:"emit_on_run_completion,omitempty" mapstructure:"emit_on_run_completion"`
	Interval            string `json:"interval,omitempty" mapstructure:"interval"`
}

// Plugin is one plugin entry.
type Plugin struct {
	Enabled         *bool               `json:"enabled,omitempty" mapstructure:"enabled"`
	ProtocolVersion int32               `json:"protocol_version,omitempty" mapstructure:"protocol_version"` // 0 = auto (R9)
	Schedule        *string             `json:"schedule,omitempty" mapstructure:"schedule"`
	Source          string              `json:"source" mapstructure:"source"`
	Policies        []string            `json:"policies,omitempty" mapstructure:"policies"`
	Config          map[string]string   `json:"config,omitempty" mapstructure:"config"`
	Labels          map[string]string   `json:"labels,omitempty" mapstructure:"labels"`
	PolicyData      map[string]any      `json:"policy_data,omitempty" mapstructure:"policy_data"`
	PolicyBehavior  map[string][]string `json:"policy_behavior,omitempty" mapstructure:"policy_behavior"`
}

// IsEnabled reports whether the plugin runs; a nil Enabled means true.
func (p *Plugin) IsEnabled() bool {
	return p != nil && (p.Enabled == nil || *p.Enabled)
}
