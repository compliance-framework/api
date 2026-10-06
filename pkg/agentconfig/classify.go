package agentconfig

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Safety is the class of one effective-config change (§3.6).
type Safety string

const (
	Safe      Safety = "safe"
	Unsafe    Safety = "unsafe"
	Forbidden Safety = "forbidden"
)

func (s Safety) rank() int {
	switch s {
	case Forbidden:
		return 2
	case Unsafe:
		return 1
	default:
		return 0
	}
}

// Change reason codes (stable; translated by the UI).
const (
	ChangeReasonLockedKey             = "locked-key"
	ChangeReasonLogging               = "logging"
	ChangeReasonDataOnly              = "data-only"
	ChangeReasonReducesScope          = "reduces-scope"
	ChangeReasonAlreadyUsed           = "already-used"
	ChangeReasonTrustedSource         = "trusted-source"
	ChangeReasonUntrustedSource       = "untrusted-source"
	ChangeReasonLocalSourceNotAllowed = "local-source-not-allowed"
	ChangeReasonNewLocalSource        = "new-local-source"
	ChangeReasonOverridableConfigFlag = "overridable-config-flag"
	ChangeReasonConfigNotOverridable  = "config-not-overridable"
	ChangeReasonNewEnvReference       = "new-env-reference"
	ChangeReasonForbiddenEnvReference = "forbidden-env-reference"
	ChangeReasonReenablePlugin        = "reenables-plugin"
)

// WillApply reasons besides ReasonUnsafeChanges / ReasonForbiddenChanges.
const (
	WillApplyReasonModeOff    = "mode-off"
	WillApplyReasonModeReport = "mode-report"
)

// Change is one classified difference between the base and the effective config.
type Change struct {
	Path   string `json:"path"` // RFC 6901 pointer
	Safety Safety `json:"safety"`
	Reason string `json:"reason"`
	Value  string `json:"value,omitempty"` // the source / env name that triggered the class
}

// Classify diffs Merge(base, overlay) against base and classifies every changed path. rc
// must be normalized. A locked key in the raw overlay is Forbidden even though Merge strips
// it. An overlay null is a deletion and is classified as one; an omitted key produces no
// Change. The result is sorted by Path, then Value.
//
// Re-enabling a plugin the base disables is Unsafe (reenables-plugin) unless its source is
// trusted (trusted-source). Its other parts are classified as if the plugin were new, since a
// disabled plugin's sources are not already used: a local plugin source goes through the
// source rules (Forbidden unless apply_all with allow_local_sources, as for a new plugin),
// every policy entry it keeps goes through the source rules, and every ${env:} reference in
// its config is a new reference. By design, apply_safe accepts the rest of a plugin's data
// without a host opt-in: schedule, labels, policy_data, policy_behavior, protocol_version and
// disabling a plugin are Safe (data-only), and removing a plugin or policy entries is Safe
// (reduces-scope). So a remote editor can change the policy inputs that decide pass/fail,
// or stop a plugin from running, on an apply_safe host.
func Classify(base Config, overlay json.RawMessage, rc RemoteConfig) ([]Change, error) {
	raw, err := decodeAny(overlay)
	if err != nil {
		return nil, fmt.Errorf("classify: decode overlay: %w", err)
	}
	var changes []Change
	if obj, ok := raw.(map[string]any); ok {
		for _, k := range LockedKeys {
			if _, present := obj[k]; present {
				changes = append(changes, Change{Path: Pointer(k), Safety: Forbidden, Reason: ChangeReasonLockedKey})
			}
		}
	} else if raw != nil {
		return nil, fmt.Errorf("classify: overlay must be a JSON object")
	}

	eff, err := Merge(base, overlay)
	if err != nil {
		return nil, fmt.Errorf("classify: %w", err)
	}
	cl := classifier{rc: rc, used: usedSources(base)}
	changes = append(changes, cl.classify(base, eff)...)
	slices.SortFunc(changes, func(a, b Change) int {
		return cmp.Or(strings.Compare(a.Path, b.Path), strings.Compare(a.Value, b.Value), strings.Compare(a.Reason, b.Reason))
	})
	return slices.Compact(changes), nil
}

// WillApply decides whether an agent in rc.Mode applies a revision with these changes:
// off -> (false, "mode-off"); report -> (false, "mode-report"); any Forbidden ->
// (false, "forbidden-changes") in every apply mode (R23); apply_safe with any Unsafe ->
// (false, "unsafe-changes"); otherwise (true, "").
func WillApply(rc RemoteConfig, changes []Change) (bool, string) {
	switch rc.Mode {
	case ModeApplySafe, ModeApplyAll:
	case ModeReport:
		return false, WillApplyReasonModeReport
	default:
		return false, WillApplyReasonModeOff
	}
	worst := Safe
	for _, c := range changes {
		if c.Safety.rank() > worst.rank() {
			worst = c.Safety
		}
	}
	switch {
	case worst == Forbidden:
		return false, ReasonForbiddenChanges
	case worst == Unsafe && rc.Mode == ModeApplySafe:
		return false, ReasonUnsafeChanges
	}
	return true, ""
}

type classifier struct {
	rc   RemoteConfig
	used map[string]bool
}

// usedSources is every plugin source and policy entry of the base's enabled plugins. A
// disabled plugin's sources do not count: the host chose not to run them, so pointing
// another plugin at one is a new source, not an already-used one.
func usedSources(base Config) map[string]bool {
	used := map[string]bool{}
	for _, p := range base.Plugins {
		if p == nil || !p.IsEnabled() {
			continue
		}
		if p.Source != "" {
			used[p.Source] = true
		}
		for _, e := range p.Policies {
			used[e] = true
		}
	}
	return used
}

func (cl classifier) sourceClass(path, s string) Change {
	switch {
	case cl.used[s]:
		return Change{Path: path, Safety: Safe, Reason: ChangeReasonAlreadyUsed, Value: s}
	case KindOf(s) == SourceKindLocal:
		if cl.rc.Mode == ModeApplyAll && cl.rc.AllowLocalSources {
			return Change{Path: path, Safety: Unsafe, Reason: ChangeReasonNewLocalSource, Value: s}
		}
		return Change{Path: path, Safety: Forbidden, Reason: ChangeReasonLocalSourceNotAllowed, Value: s}
	case MatchTrustedSource(cl.rc, s):
		return Change{Path: path, Safety: Safe, Reason: ChangeReasonTrustedSource, Value: s}
	default:
		return Change{Path: path, Safety: Unsafe, Reason: ChangeReasonUntrustedSource, Value: s}
	}
}

func (cl classifier) classify(base, eff Config) []Change {
	var out []Change
	if base.Verbosity != eff.Verbosity {
		out = append(out, Change{Path: "/verbosity", Safety: Safe, Reason: ChangeReasonLogging})
	}
	for _, p := range changedLeaves("/agent_evidence", base.AgentEvidence, eff.AgentEvidence) {
		out = append(out, Change{Path: p, Safety: Safe, Reason: ChangeReasonLogging})
	}

	for _, name := range unionMapKeys(base.Plugins, eff.Plugins) {
		ptr := Pointer("plugins", name)
		bp, inBase := base.Plugins[name]
		ep, inEff := eff.Plugins[name]
		if inBase && bp != nil && (!inEff || ep == nil) {
			out = append(out, Change{Path: ptr, Safety: Safe, Reason: ChangeReasonReducesScope})
			continue
		}
		if ep == nil {
			continue
		}
		if bp == nil {
			bp = &Plugin{} // a new plugin is the class of its parts
		}
		out = append(out, cl.classifyPlugin(ptr, name, bp, ep)...)
	}
	return out
}

func (cl classifier) classifyPlugin(ptr, name string, bp, ep *Plugin) []Change {
	var out []Change
	dataOnly := func(field string, a, b any) {
		if !jsonValueEqual(a, b) {
			out = append(out, Change{Path: ptr + "/" + field, Safety: Safe, Reason: ChangeReasonDataOnly})
		}
	}
	dataOnly("schedule", bp.Schedule, ep.Schedule)
	dataOnly("labels", nilIfEmptyMap(bp.Labels), nilIfEmptyMap(ep.Labels))
	dataOnly("policy_behavior", nilIfEmptyMap(bp.PolicyBehavior), nilIfEmptyMap(ep.PolicyBehavior))
	dataOnly("protocol_version", bp.ProtocolVersion, ep.ProtocolVersion)
	reenabled := !bp.IsEnabled() && ep.IsEnabled()
	if reenabled {
		// Re-enabling a plugin the host disabled runs it again: Unsafe unless trusted.
		if MatchTrustedSource(cl.rc, ep.Source) {
			out = append(out, Change{Path: ptr + "/enabled", Safety: Safe, Reason: ChangeReasonTrustedSource, Value: ep.Source})
		} else {
			out = append(out, Change{Path: ptr + "/enabled", Safety: Unsafe, Reason: ChangeReasonReenablePlugin, Value: ep.Source})
		}
		// A kept local source is not already used either: classify it like a new plugin's, so
		// allow_local_sources cannot be bypassed by re-enabling. A changed source is classified
		// below.
		if bp.Source == ep.Source && KindOf(ep.Source) == SourceKindLocal {
			out = append(out, cl.sourceClass(ptr+"/source", ep.Source))
		}
		// Its policies are not already used (usedSources skips disabled plugins), so the
		// entries it keeps are classified like new ones; added entries are classified below.
		for _, e := range ep.Policies {
			if slices.Contains(bp.Policies, e) {
				out = append(out, cl.sourceClass(ptr+"/policies", e))
			}
		}
	} else {
		dataOnly("enabled", bp.IsEnabled(), ep.IsEnabled())
	}
	dataOnly("policy_data", nilIfEmptyMap(bp.PolicyData), nilIfEmptyMap(ep.PolicyData))

	if bp.Source != ep.Source {
		out = append(out, cl.sourceClass(ptr+"/source", ep.Source))
	}

	if !slices.Equal(bp.Policies, ep.Policies) {
		polPtr := ptr + "/policies"
		added := false
		for _, e := range ep.Policies {
			if slices.Contains(bp.Policies, e) {
				continue
			}
			added = true
			out = append(out, cl.sourceClass(polPtr, e))
		}
		if !added {
			out = append(out, Change{Path: polPtr, Safety: Safe, Reason: ChangeReasonReducesScope})
		}
	}

	for _, key := range unionMapKeys(bp.Config, ep.Config) {
		bv, inBase := bp.Config[key]
		ev, inEff := ep.Config[key]
		unchanged := inBase == inEff && bv == ev
		if unchanged && !reenabled {
			continue
		}
		kptr := ptr + "/config/" + EscapePointerToken(key)
		// Env rule (R24): a variable not referenced by the base value at the same pointer. A
		// re-enabled plugin's references are not in use, so all of them count as new.
		baseRefs := EnvRefs(bv)
		if reenabled {
			baseRefs = nil
		}
		var envChanges []Change
		for _, n := range EnvRefs(ev) {
			if slices.Contains(baseRefs, n) {
				continue
			}
			if IsForbiddenEnvName(n) {
				envChanges = append(envChanges, Change{Path: kptr, Safety: Forbidden, Reason: ChangeReasonForbiddenEnvReference, Value: n})
			} else {
				envChanges = append(envChanges, Change{Path: kptr, Safety: Unsafe, Reason: ChangeReasonNewEnvReference, Value: n})
			}
		}
		if len(envChanges) > 0 {
			out = append(out, envChanges...)
			continue
		}
		if unchanged {
			continue // re-enabled: only the env references of values the overlay keeps are checked
		}
		if MatchOverridableConfigFlag(cl.rc, name, key) {
			out = append(out, Change{Path: kptr, Safety: Safe, Reason: ChangeReasonOverridableConfigFlag})
		} else {
			out = append(out, Change{Path: kptr, Safety: Unsafe, Reason: ChangeReasonConfigNotOverridable})
		}
	}
	return out
}

// changedLeaves returns the pointers (under prefix) of the leaves that differ between two
// JSON-encodable values; a nil side counts as an empty object.
func changedLeaves(prefix string, a, b any) []string {
	da := toDecoded(a)
	db := toDecoded(b)
	var paths []string
	leafDiffPaths(prefix, da, db, da != nil, db != nil, &paths)
	return paths
}

func toDecoded(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	d, err := decodeAny(raw)
	if err != nil {
		return nil
	}
	return d
}

func jsonValueEqual(a, b any) bool {
	return jsonEqual(toDecoded(a), toDecoded(b))
}

// nilIfEmptyMap treats an empty map like an absent one (omitempty semantics).
func nilIfEmptyMap[K comparable, V any](m map[K]V) any {
	if len(m) == 0 {
		return nil
	}
	return m
}

func unionMapKeys[V any](a, b map[string]V) []string {
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}
