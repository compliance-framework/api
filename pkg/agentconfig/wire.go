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
	ReasonPolicyErrors       = "policy-errors"  // parse/compile/authored-test/builtin failures
	ReasonDownloadFailed     = "download-failed"
	ReasonEnvMissing         = "env-missing"          // R24
	ReasonUnsupportedByAgent = "unsupported-by-agent" // overlay uses a feature this agent version lacks
	ReasonCacheCorrupt       = "cache-corrupt"
	ReasonInternal           = "internal"
)

// Reasons is the full report reason vocabulary.
var Reasons = []string{
	ReasonUnsafeChanges, ReasonForbiddenChanges, ReasonInvalidConfig, ReasonInvalidType,
	ReasonUnknownField, ReasonPolicyErrors, ReasonDownloadFailed, ReasonEnvMissing,
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
	Hostname          string               `json:"hostname,omitempty"`      // <= 255
	AgentVersion      string               `json:"agent-version,omitempty"` // <= 64
	Mode              string               `json:"mode"`
	Daemon            bool                 `json:"daemon"` // false = one-shot run; pruned after 24h (R10, R37)
	AppliedRevision   *int64               `json:"applied-revision"`
	AttemptedRevision *int64               `json:"attempted-revision,omitempty"`
	Status            string               `json:"status"`
	Reason            string               `json:"reason,omitempty"`
	Error             *string              `json:"error"`               // <= 8 KiB, truncated server-side
	Truncated         bool                 `json:"truncated,omitempty"` // agent dropped/trimmed parts to fit MaxReportBytes (R10)
	Warnings          []FieldError         `json:"warnings,omitempty"`  // R41: tolerated file-origin problems
	Base              json.RawMessage      `json:"base" swaggertype:"object"`
	Effective         json.RawMessage      `json:"effective" swaggertype:"object"`
	EffectiveDigest   string               `json:"effective-digest"`
	PolicyBundles     []PolicyBundleReport `json:"policy-bundles,omitempty"`
	PolicyErrors      []PolicyError        `json:"policy-errors,omitempty"`
	Unsafe            []Change             `json:"unsafe,omitempty"`
	RemoteConfig      *RemoteConfig        `json:"remote-config,omitempty"` // normalized; snake_case inside
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
	// InlinePolicies says whether the plugin honours policy_id, so it may be given inline
	// policies (R79): supported, unsupported, or unknown (no build info, or a replace or
	// devel build). The agent decides it from LibVersion. Empty for older agents.
	InlinePolicies string `json:"inline-policies,omitempty" enums:"supported,unsupported,unknown"`
}

// PluginReport.InlinePolicies values (R79). The agent rejects an overlay that gives inline
// policies to an unsupported plugin (PolicyCodePluginLibInlineUnsupported) and warns for an
// unknown one.
const (
	InlinePoliciesSupported   = "supported"   // built against an agent library with R74
	InlinePoliciesUnsupported = "unsupported" // built against an older agent library
	InlinePoliciesUnknown     = "unknown"     // no build info, or a replace or devel build
)

// InlinePoliciesValues is the PluginReport.InlinePolicies vocabulary.
var InlinePoliciesValues = []string{InlinePoliciesSupported, InlinePoliciesUnsupported, InlinePoliciesUnknown}

// PolicyBundleReport describes one policy path the agent loaded.
type PolicyBundleReport struct {
	Source  string               `json:"source"`
	Digest  string               `json:"digest"`            // tree digest on main (R10)
	Extends *PolicyExtendsReport `json:"extends,omitempty"` // inline bundles with extends: the vendor tree (R10)
	Files   []PolicyFileReport   `json:"files"`             // inline: the materialized tree; others: their tree
	// ArtifactDigest names the policy bundle artifact (sha256:<hex> of the canonical tar,
	// see docs/artifacts.md) the agent uploaded for this tree, so its sources can be read
	// through GET /api/artifacts/{digest}/files (R62). Empty when the upload failed or the
	// agent does not upload. Agents keep it when they drop Files to fit the report size.
	// The API checks its format only, not that the artifact exists.
	ArtifactDigest string `json:"artifact-digest,omitempty"`
	// PluginPath is the exact path string the agent passes to plugins for this source, which
	// plugins seed evidence UUIDs with (R77). It may be un-cleaned (for example "./x" or
	// "x/"). Build a policy_id that continues a file's evidence stream as the literal
	// PluginPath + "/" + file, not path.Join: plugins seeded OPA's cleaned file with the
	// literal PluginPath, and policyeval.SeedPath cleans the ID for the file seed but trims
	// the raw ID for the path seed, so only the literal form keeps "./x" or "x/" in
	// _policy_path. Empty from older agents.
	PluginPath string `json:"plugin-path,omitempty"`
}

// PolicyExtendsReport is the vendor tree an inline bundle extends.
type PolicyExtendsReport struct {
	Source string             `json:"source"`
	Digest string             `json:"digest"`
	Files  []PolicyFileReport `json:"files"`
	// ArtifactDigest names the artifact of the vendor tree alone; see
	// PolicyBundleReport.ArtifactDigest.
	ArtifactDigest string `json:"artifact-digest,omitempty"`
	// PluginPath is the exact (literal) path the agent would pass to plugins for the extends
	// source if a plugin loaded it directly (R78). Clients build continuity ids as
	// PluginPath + "/" + file (literal concatenation, see PolicyBundleReport.PluginPath). It
	// lets a client keep a vendor file's evidence stream after an inline bundle has replaced
	// the source in every plugin, when no policy-bundles[] entry names the source any more.
	// Empty from older agents.
	PluginPath string `json:"plugin-path,omitempty"`
}

// PolicyBundleExtendsReport is an alias of PolicyExtendsReport (the name the agent LLD uses).
type PolicyBundleExtendsReport = PolicyExtendsReport

// PolicyFileReport is one file of a policy tree.
type PolicyFileReport struct {
	Path    string `json:"path"` // relative to the policy root
	SHA256  string `json:"sha256"`
	Package string `json:"package,omitempty"`
}
