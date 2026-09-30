package agentconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ValidateOverlay validates an overlay ON ITS OWN (no base) and returns nil or
// ValidationErrors. It is the only strict decoder in the package (R27, R51): unknown keys are
// rejected everywhere, every leaf may be null (RFC 7396 delete) and there is no type
// coercion. Rules:
//
//	O1  must be a JSON object ({} allowed)
//	O2  compact size <= MaxOverlayBytes, or MaxOverlayBytesWithBundles when policy_bundles
//	    is present and non-null
//	O3  no locked key (api, daemon, remote_config), even with a null value
//	O4  unknown keys are rejected
//	O5  types: verbosity integer 0-2; agent_evidence.{enabled,emit_on_run_completion} bool,
//	    interval a Go duration >= 0; plugins.*.config and labels values strings (or null);
//	    policy_behavior values string arrays; protocol_version 1 or 2 (explicit 0 rejected,
//	    R9); schedule a string
//	O6  plugin names set by the overlay and bundle names match PluginNamePattern
//	O7  schedule parses with ParseSchedule
//	O8  source (when non-null) is non-empty and not inline:; policy entries are non-empty
//	    and inline: entries carry a valid bundle name
//	O9  ${env:NAME} only in plugins.*.config values; NAME must not be forbidden
//	O10 no string value equals MaskedValue
//	O11 policy_bundles shape via the bundle checks (per bundle patch)
func ValidateOverlay(overlay json.RawMessage) error {
	v, err := decodeAny(overlay)
	if err != nil {
		return ValidationErrors{{Path: "", Code: FieldCodeParse, Message: fmt.Sprintf("overlay is not valid JSON: %s", err.Error())}}
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return ValidationErrors{{Path: "", Code: FieldCodeParse, Message: "overlay must be a JSON object"}}
	}

	ov := &overlayValidator{}

	// O2: size of the compact encoding.
	var compact bytes.Buffer
	if err := json.Compact(&compact, overlay); err == nil {
		limit := MaxOverlayBytes
		if pb, present := obj["policy_bundles"]; present && pb != nil {
			limit = MaxOverlayBytesWithBundles
		}
		if compact.Len() > limit {
			ov.add("", FieldCodeSize, "overlay is %d bytes; the limit is %d", compact.Len(), limit)
		}
	}

	for _, key := range sortedKeys(obj) {
		val := obj[key]
		ptr := Pointer(key)
		switch key {
		case "api", "daemon", "remote_config":
			ov.add(ptr, FieldCodeLockedKey, "%s is set locally only and cannot be changed remotely", key)
		case "verbosity":
			if val != nil {
				if n, ok := ov.integer(ptr, val); ok && (n < 0 || n > 2) {
					ov.add(ptr, FieldCodeInvalidValue, "must be 0, 1 or 2")
				}
			}
		case "plugins":
			ov.plugins(ptr, val)
		case "agent_evidence":
			ov.agentEvidence(ptr, val)
		case "policy_bundles":
			ov.policyBundles(ptr, val)
		default:
			ov.add(ptr, FieldCodeUnknownField, "unknown field %q", key)
		}
	}

	// O9 and O10 apply to every string in the document.
	walkStrings("", obj, func(ptr, s string) {
		if s == MaskedValue {
			ov.add(ptr, FieldCodeMaskedValue, "redacted placeholder %q cannot be submitted; set the real value or omit the key", MaskedValue)
		}
		ov.envRefs(ptr, s, isPluginConfigValuePointer(ptr))
	})

	return asError(ov.errs)
}

type overlayValidator struct {
	errs []FieldError
}

func (ov *overlayValidator) add(ptr, code, format string, args ...any) {
	ov.errs = append(ov.errs, FieldError{Path: ptr, Code: code, Message: fmt.Sprintf(format, args...)})
}

func (ov *overlayValidator) object(ptr string, v any) (map[string]any, bool) {
	obj, ok := v.(map[string]any)
	if !ok {
		ov.add(ptr, FieldCodeInvalidType, "must be an object")
	}
	return obj, ok
}

func (ov *overlayValidator) str(ptr string, v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		ov.add(ptr, FieldCodeInvalidType, "must be a string")
	}
	return s, ok
}

func (ov *overlayValidator) boolean(ptr string, v any) {
	if _, ok := v.(bool); !ok {
		ov.add(ptr, FieldCodeInvalidType, "must be a boolean")
	}
}

func (ov *overlayValidator) integer(ptr string, v any) (int64, bool) {
	n, ok := v.(json.Number)
	if ok {
		if i, err := n.Int64(); err == nil {
			return i, true
		}
	}
	ov.add(ptr, FieldCodeInvalidType, "must be an integer")
	return 0, false
}

// stringMap checks an object whose values must be strings or null.
func (ov *overlayValidator) stringMap(ptr string, v any) {
	if v == nil {
		return
	}
	obj, ok := ov.object(ptr, v)
	if !ok {
		return
	}
	for _, k := range sortedKeys(obj) {
		if obj[k] != nil {
			ov.str(appendPointer(ptr, k), obj[k])
		}
	}
}

// stringArray checks an array of strings and returns them (nil for null or invalid).
func (ov *overlayValidator) stringArray(ptr string, v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]any)
	if !ok {
		ov.add(ptr, FieldCodeInvalidType, "must be an array of strings")
		return nil, false
	}
	out := make([]string, 0, len(arr))
	valid := true
	for i, item := range arr {
		s, ok := ov.str(appendPointer(ptr, strconv.Itoa(i)), item)
		if !ok {
			valid = false
			continue
		}
		out = append(out, s)
	}
	return out, valid
}

func (ov *overlayValidator) plugins(ptr string, v any) {
	if v == nil {
		return
	}
	obj, ok := ov.object(ptr, v)
	if !ok {
		return
	}
	for _, name := range sortedKeys(obj) {
		pptr := appendPointer(ptr, name)
		val := obj[name]
		if val == nil {
			continue // RFC 7396: delete the plugin (reduces scope)
		}
		if !PluginNamePattern.MatchString(name) {
			ov.add(pptr, FieldCodePattern, "plugin name %q must match %s", name, PluginNamePattern.String())
		}
		plugin, ok := ov.object(pptr, val)
		if !ok {
			continue
		}
		for _, key := range sortedKeys(plugin) {
			fv := plugin[key]
			fptr := appendPointer(pptr, key)
			if fv == nil {
				switch key {
				case "enabled", "protocol_version", "schedule", "source", "policies", "config", "labels", "policy_data", "policy_behavior":
					continue // null deletes the key; the agent default applies
				}
			}
			switch key {
			case "enabled":
				ov.boolean(fptr, fv)
			case "protocol_version":
				if n, ok := ov.integer(fptr, fv); ok && n != 1 && n != 2 {
					if n == 0 {
						ov.add(fptr, FieldCodeInvalidValue, "must be 1 or 2; omit the key to keep the file value or send null for auto-detection")
					} else {
						ov.add(fptr, FieldCodeInvalidValue, "must be 1 or 2")
					}
				}
			case "schedule":
				if s, ok := ov.str(fptr, fv); ok {
					if _, err := ParseSchedule(s); err != nil {
						ov.add(fptr, FieldCodeCron, "invalid cron schedule: %s", err.Error())
					}
				}
			case "source":
				if s, ok := ov.str(fptr, fv); ok {
					ov.pluginSource(fptr, s)
				}
			case "policies":
				entries, _ := ov.stringArray(fptr, fv)
				for i, e := range entries {
					ov.policyEntry(appendPointer(fptr, strconv.Itoa(i)), e)
				}
			case "config", "labels":
				ov.stringMap(fptr, fv)
			case "policy_data":
				ov.object(fptr, fv)
			case "policy_behavior":
				if behavior, ok := ov.object(fptr, fv); ok {
					for _, k := range sortedKeys(behavior) {
						ov.stringArray(appendPointer(fptr, k), behavior[k])
					}
				}
			default:
				ov.add(fptr, FieldCodeUnknownField, "unknown field %q", key)
			}
		}
	}
}

func (ov *overlayValidator) pluginSource(ptr, s string) {
	switch {
	case strings.TrimSpace(s) == "":
		ov.add(ptr, FieldCodeSource, "plugin source must not be empty")
	case IsInlineSource(s):
		ov.add(ptr, FieldCodeSource, "plugin source must not be an inline bundle")
	}
}

func (ov *overlayValidator) policyEntry(ptr, e string) {
	if strings.TrimSpace(e) == "" {
		ov.add(ptr, FieldCodeSource, "policy entry must not be empty")
		return
	}
	if IsInlineSource(e) {
		name, ok := InlineBundleName(e)
		if !ok || !BundleNamePattern.MatchString(name) {
			ov.add(ptr, FieldCodeSource, "inline policy entry %q must name a bundle matching %s", e, BundleNamePattern.String())
		}
	}
}

func (ov *overlayValidator) agentEvidence(ptr string, v any) {
	if v == nil {
		return
	}
	obj, ok := ov.object(ptr, v)
	if !ok {
		return
	}
	for _, key := range sortedKeys(obj) {
		fv := obj[key]
		fptr := appendPointer(ptr, key)
		switch key {
		case "enabled", "emit_on_run_completion":
			if fv != nil {
				ov.boolean(fptr, fv)
			}
		case "interval":
			if fv == nil {
				continue
			}
			if s, ok := ov.str(fptr, fv); ok {
				if msg := checkDuration(s, 0); msg != "" {
					ov.add(fptr, FieldCodeDuration, "%s", msg)
				}
			}
		default:
			ov.add(fptr, FieldCodeUnknownField, "unknown field %q", key)
		}
	}
}

func (ov *overlayValidator) policyBundles(ptr string, v any) {
	if v == nil {
		return
	}
	obj, ok := ov.object(ptr, v)
	if !ok {
		return
	}
	patches := map[string]*PolicyBundle{}
	for _, name := range sortedKeys(obj) {
		bptr := appendPointer(ptr, name)
		val := obj[name]
		if val == nil {
			continue // delete the bundle
		}
		bundleObj, ok := ov.object(bptr, val)
		if !ok {
			continue
		}
		patch := &PolicyBundle{}
		for _, key := range sortedKeys(bundleObj) {
			fv := bundleObj[key]
			fptr := appendPointer(bptr, key)
			switch key {
			case "extends":
				if fv == nil {
					continue
				}
				if s, ok := ov.str(fptr, fv); ok {
					patch.Extends = &s
				}
			case "modules":
				if fv == nil {
					continue
				}
				modules, ok := ov.object(fptr, fv)
				if !ok {
					continue
				}
				for _, p := range sortedKeys(modules) {
					if modules[p] == nil {
						continue // delete the effective module
					}
					if s, ok := ov.str(appendPointer(fptr, p), modules[p]); ok {
						if patch.Modules == nil {
							patch.Modules = map[string]string{}
						}
						patch.Modules[p] = s
					}
				}
			case "delete":
				entries, _ := ov.stringArray(fptr, fv)
				patch.Delete = entries
			case "data":
				if fv == nil {
					continue
				}
				if data, ok := ov.object(fptr, fv); ok {
					patch.Data = data
				}
			default:
				ov.add(fptr, FieldCodeUnknownField, "unknown field %q", key)
			}
		}
		patches[name] = patch
	}
	ov.errs = append(ov.errs, issuesToFieldErrors(validateBundles(patches, true))...)
}

// envRefs applies O9 to one string value.
func (ov *overlayValidator) envRefs(ptr, s string, inPluginConfig bool) {
	names := EnvRefs(s)
	if len(names) == 0 {
		return
	}
	if !inPluginConfig {
		ov.add(ptr, FieldCodeEnvLocation, "${env:...} references are only resolved in plugins.*.config values")
		return
	}
	for _, n := range names {
		if IsForbiddenEnvName(n) {
			ov.add(ptr, FieldCodeForbiddenEnv, "${env:%s} may not be referenced", n)
		}
	}
}

// isPluginConfigValuePointer reports whether ptr is exactly /plugins/<p>/config/<k>.
func isPluginConfigValuePointer(ptr string) bool {
	segs := SplitPointer(ptr)
	return len(segs) == 4 && segs[0] == "plugins" && segs[2] == "config"
}

// walkStrings calls fn for every string value in a decoded JSON tree (object keys are not
// visited), with the value's pointer.
func walkStrings(ptr string, v any, fn func(ptr, s string)) {
	switch t := v.(type) {
	case string:
		fn(ptr, t)
	case map[string]any:
		for _, k := range sortedKeys(t) {
			walkStrings(appendPointer(ptr, k), t[k], fn)
		}
	case []any:
		for i, item := range t {
			walkStrings(appendPointer(ptr, strconv.Itoa(i)), item, fn)
		}
	}
}

// checkDuration returns "" when s is a Go duration >= min, else a message.
func checkDuration(s string, min time.Duration) string {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Sprintf("must be a duration such as 30s or 5m: %s", err.Error())
	}
	if d < min {
		if min == 0 {
			return "must not be negative"
		}
		return fmt.Sprintf("must be at least %s", min)
	}
	return ""
}

// ValidateEditable checks an effective config except the locked blocks (api, daemon,
// remote_config). The API uses it on redacted reported bases merged with an overlay, so it
// never rejects masked values or a missing client secret. Rules: verbosity >= 0;
// agent_evidence.interval a non-negative duration; every plugin non-nil with a non-empty,
// non-inline source, a parseable schedule, protocol_version in {0,1,2}, non-empty policy
// entries whose inline:<b> references resolve in PolicyBundles; env references obey O9;
// PolicyBundles pass ValidateBundles.
func (c Config) ValidateEditable() error {
	return asError(c.validateEditable())
}

// Validate is the agent's full check of an effective config: ValidateEditable plus the api
// block (url required, both or neither credential, client_id a UUID) and remote_config (mode
// enum, poll_interval >= MinPollInterval, valid glob patterns). File-origin leniency (R34)
// and the explicit-0 protocol_version file check (R9) are agent concerns: the agent chooses
// which FieldErrors to downgrade.
func (c Config) Validate() error {
	errs := c.validateEditable()
	errs = append(errs, c.validateAPI()...)
	errs = append(errs, c.validateRemoteConfig()...)
	return asError(errs)
}

func (c Config) validateEditable() []FieldError {
	ov := &overlayValidator{}
	if c.Verbosity < 0 {
		ov.add("/verbosity", FieldCodeInvalidValue, "must not be negative")
	}
	if c.AgentEvidence != nil && strings.TrimSpace(c.AgentEvidence.Interval) != "" {
		if msg := checkDuration(c.AgentEvidence.Interval, 0); msg != "" {
			ov.add("/agent_evidence/interval", FieldCodeDuration, "%s", msg)
		}
	}
	for _, name := range sortedKeys(c.Plugins) {
		p := c.Plugins[name]
		pptr := Pointer("plugins", name)
		if p == nil {
			ov.add(pptr, FieldCodeRequired, "plugin %q has no configuration", name)
			continue
		}
		switch {
		case strings.TrimSpace(p.Source) == "":
			ov.add(pptr+"/source", FieldCodeRequired, "plugin source is required")
		case IsInlineSource(p.Source):
			ov.add(pptr+"/source", FieldCodeSource, "plugin source must not be an inline bundle")
		}
		if p.Schedule != nil {
			if _, err := ParseSchedule(*p.Schedule); err != nil {
				ov.add(pptr+"/schedule", FieldCodeCron, "invalid cron schedule: %s", err.Error())
			}
		}
		if p.ProtocolVersion < 0 || p.ProtocolVersion > 2 {
			ov.add(pptr+"/protocol_version", FieldCodeInvalidValue, "must be 1 or 2 (0 or unset = auto)")
		}
		for i, e := range p.Policies {
			eptr := pptr + "/policies/" + strconv.Itoa(i)
			ov.policyEntry(eptr, e)
			if name, ok := InlineBundleName(e); ok && BundleNamePattern.MatchString(name) {
				if b, found := c.PolicyBundles[name]; !found || b == nil {
					ov.add(eptr, FieldCodeUnresolvedRef, "policy bundle %q is not defined", name)
				}
			}
		}
	}
	ov.errs = append(ov.errs, issuesToFieldErrors(validateBundles(c.PolicyBundles, false))...)

	// O9 over the editable part of the document.
	if raw, err := json.Marshal(c.clone().editableView()); err == nil {
		if doc, err := decodeAny(raw); err == nil {
			walkStrings("", doc, func(ptr, s string) {
				ov.envRefs(ptr, s, isPluginConfigValuePointer(ptr))
			})
		}
	}
	return ov.errs
}

// editableView is c without the locked blocks.
func (c Config) editableView() Config {
	out := c
	out.API = nil
	out.RemoteConfig = nil
	out.Daemon = false
	return out
}

func (c Config) validateAPI() []FieldError {
	ov := &overlayValidator{}
	switch {
	case c.API == nil:
		ov.add("/api", FieldCodeRequired, "no api config specified")
		return ov.errs
	case strings.TrimSpace(c.API.URL) == "":
		ov.add("/api/url", FieldCodeRequired, "api url must be configured")
	}
	if c.API.HasPartialAuth() {
		ov.add("/api/auth", FieldCodeRequired, "api auth requires both client_id and client_secret when configured")
	}
	if c.API.HasAuth() {
		if _, err := uuid.Parse(strings.TrimSpace(c.API.Auth.ClientID)); err != nil {
			ov.add("/api/auth/client_id", FieldCodeInvalidValue, "api auth client_id must be a valid UUID")
		}
	}
	return ov.errs
}

func (c Config) validateRemoteConfig() []FieldError {
	ov := &overlayValidator{}
	rc := c.RemoteConfig
	if rc == nil {
		return nil
	}
	if rc.Mode != "" && !slices.Contains([]string{ModeOff, ModeReport, ModeApplySafe, ModeApplyAll}, rc.Mode) {
		ov.add("/remote_config/mode", FieldCodeInvalidValue, "mode must be one of off, report, apply_safe, apply_all")
	}
	if strings.TrimSpace(rc.PollInterval) != "" {
		if msg := checkDuration(rc.PollInterval, MinPollInterval); msg != "" {
			ov.add("/remote_config/poll_interval", FieldCodeDuration, "%s", msg)
		}
	}
	for i, p := range rc.TrustedSources {
		if _, err := path.Match(p, ""); err != nil {
			ov.add("/remote_config/trusted_sources/"+strconv.Itoa(i), FieldCodePattern, "invalid glob pattern %q", p)
		}
	}
	for i, entry := range rc.OverridableConfigFlags {
		pluginGlob, keyGlob, scoped := strings.Cut(entry, ":")
		globs := []string{entry}
		if scoped {
			globs = []string{pluginGlob, keyGlob}
		}
		for _, g := range globs {
			if _, err := path.Match(g, ""); err != nil {
				ov.add("/remote_config/overridable_config_flags/"+strconv.Itoa(i), FieldCodePattern, "invalid glob pattern %q", entry)
				break
			}
		}
	}
	return ov.errs
}
