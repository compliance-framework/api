package agentconfig

import (
	"regexp"
	"strconv"
)

// secretKeyPattern matches config/data keys whose values are treated as secrets.
var secretKeyPattern = regexp.MustCompile(`(?i)(secret|token|password|passwd|key|credential|auth)`)

// RedactOption configures Redact and Digest.
type RedactOption func(*redactOpts)

type redactOpts struct {
	masked map[string]bool
}

// WithMaskedPointers masks the values at these RFC 6901 pointers. The agent passes the
// plugin config values that came from viper env (CCF_PLUGINS_<P>_CONFIG_<K>) rather than from
// placeholders (R25, R44). Pass the SAME pointers to Redact and Digest (R55).
func WithMaskedPointers(ptrs ...string) RedactOption {
	return func(o *redactOpts) {
		if o.masked == nil {
			o.masked = map[string]bool{}
		}
		for _, p := range ptrs {
			o.masked[p] = true
		}
	}
}

// Redact returns a deep copy of c with api.auth.client_secret cleared and secret-like values
// replaced by MaskedValue. Apply it to the UNRESOLVED config (placeholders intact). It is
// idempotent.
//
// Mask rule, under plugins.*.config and plugins.*.policy_data (any depth), for each string
// value:
//  1. a value containing an ${env:...} reference is kept verbatim;
//  2. else a value at a pointer given to WithMaskedPointers becomes MaskedValue;
//  3. else a value whose key matches (?i)(secret|token|password|passwd|key|credential|auth)
//     becomes MaskedValue.
//
// Non-string values under a matching key also become MaskedValue.
func Redact(c Config, opts ...RedactOption) Config {
	var o redactOpts
	for _, opt := range opts {
		opt(&o)
	}
	out := c.clone()
	if out.API != nil && out.API.Auth != nil {
		out.API.Auth.ClientSecret = ""
	}
	for pluginName, p := range out.Plugins {
		if p == nil {
			continue
		}
		for key, value := range p.Config {
			ptr := Pointer("plugins", pluginName, "config", key)
			if o.shouldMask(ptr, key, value) {
				p.Config[key] = MaskedValue
			}
		}
		if p.PolicyData != nil {
			p.PolicyData = o.redactMap(Pointer("plugins", pluginName, "policy_data"), p.PolicyData)
		}
	}
	return out
}

// shouldMask applies the mask rule to one string value.
func (o redactOpts) shouldMask(ptr, key, value string) bool {
	if len(EnvRefs(value)) > 0 {
		return false
	}
	if o.masked[ptr] {
		return true
	}
	return secretKeyPattern.MatchString(key)
}

// redactMap redacts the entries of a free-form object.
func (o redactOpts) redactMap(ptr string, m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, val := range m {
		out[k] = o.redactTree(appendPointer(ptr, k), k, val)
	}
	return out
}

// redactTree returns a redacted copy of a free-form value. key is the nearest enclosing map
// key.
func (o redactOpts) redactTree(ptr, key string, v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		if o.shouldMask(ptr, key, t) {
			return MaskedValue
		}
		return t
	}
	// A non-string value under a matching key (or at a masked pointer) is masked whole.
	if o.masked[ptr] || (key != "" && secretKeyPattern.MatchString(key)) {
		return MaskedValue
	}
	switch t := v.(type) {
	case map[string]any:
		return o.redactMap(ptr, t)
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = o.redactTree(appendPointer(ptr, strconv.Itoa(i)), key, val)
		}
		return out
	default:
		return t
	}
}
