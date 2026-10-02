package agentconfig

import (
	"encoding/json"
	"time"
)

// Instance statuses. The agent sends applied, rejected, failed or not-applicable (R10); the
// server additionally derives pending and unknown.
const (
	StatusApplied       = "applied"
	StatusRejected      = "rejected"
	StatusFailed        = "failed"
	StatusNotApplicable = "not-applicable"
	StatusPending       = "pending" // server-derived only
	StatusUnknown       = "unknown" // server-derived only
)

// AgentStatuses are the statuses an agent may report.
var AgentStatuses = []string{StatusApplied, StatusRejected, StatusFailed, StatusNotApplicable}

// Report reasons (R42). The API rejects any other value.
const (
	ReasonUnsafeChanges      = "unsafe-changes"
	ReasonForbiddenChanges   = "forbidden-changes"
	ReasonInvalidConfig      = "invalid-config" // overlay-merged config invalid, OR the local file is invalid on reload (agent keeps last-known-good, R42)
	ReasonInvalidType        = "invalid-type"   // R27 (agent strict decode)
	ReasonUnknownField       = "unknown-field"  // R27
	ReasonDownloadFailed     = "download-failed"
	ReasonEnvMissing         = "env-missing"          // R24
	ReasonUnsupportedByAgent = "unsupported-by-agent" // overlay uses a feature this agent version lacks
	ReasonCacheCorrupt       = "cache-corrupt"
	ReasonInternal           = "internal"
)

// Reasons is the full report reason vocabulary.
var Reasons = []string{
	ReasonUnsafeChanges, ReasonForbiddenChanges, ReasonInvalidConfig, ReasonInvalidType,
	ReasonUnknownField, ReasonDownloadFailed, ReasonEnvMissing,
	ReasonUnsupportedByAgent, ReasonCacheCorrupt, ReasonInternal,
}

// Modes is the remote_config.mode vocabulary.
var Modes = []string{ModeOff, ModeReport, ModeApplySafe, ModeApplyAll}

// OverlayDocument is the body of GET /api/agent/config (inside {"data": ...}).
type OverlayDocument struct {
	Revision  int64           `json:"revision"`
	Overlay   json.RawMessage `json:"overlay" swaggertype:"object"`
	CreatedAt *time.Time      `json:"created-at,omitempty"` // omitted for revision 0
}

// Report is the body of PUT /api/agent/instances/:instanceId/config-report. Envelope keys are
// kebab-case; Base, Effective and RemoteConfig contents are snake_case config documents.
type Report struct {
	Hostname          string          `json:"hostname,omitempty"`      // <= 255
	AgentVersion      string          `json:"agent-version,omitempty"` // <= 64
	Mode              string          `json:"mode"`
	Daemon            bool            `json:"daemon"` // false = one-shot run; pruned after 24h (R10, R37)
	AppliedRevision   *int64          `json:"applied-revision"`
	AttemptedRevision *int64          `json:"attempted-revision,omitempty"`
	Status            string          `json:"status"`
	Reason            string          `json:"reason,omitempty"`
	Error             *string         `json:"error"`               // <= 8 KiB, truncated server-side
	Truncated         bool            `json:"truncated,omitempty"` // agent dropped/trimmed parts to fit MaxReportBytes (R10)
	Warnings          []FieldError    `json:"warnings,omitempty"`  // R41: tolerated file-origin problems
	Base              json.RawMessage `json:"base" swaggertype:"object"`
	Effective         json.RawMessage `json:"effective" swaggertype:"object"`
	EffectiveDigest   string          `json:"effective-digest"`
	Unsafe            []Change        `json:"unsafe,omitempty"`
	RemoteConfig      *RemoteConfig   `json:"remote-config,omitempty"` // normalized; snake_case inside
	// Plugins are the instance's plugins and the agent library each was built with (R76),
	// so the UI can show policy compatibility before a save. Older agents omit it.
	Plugins []PluginReport `json:"plugins,omitempty"`
}

// PluginReport is one plugin of an instance (R76).
type PluginReport struct {
	Name   string `json:"name"`             // the plugin's key under plugins in the config
	Source string `json:"source,omitempty"` // the configured source
	// LibVersion is the version of github.com/compliance-framework/agent the plugin binary
	// was built with, from its Go build info. Empty when unknown: no build info, or a
	// replace or devel build.
	LibVersion string `json:"lib-version,omitempty"`
}
