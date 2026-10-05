package agentconfig

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// EnvRefPattern matches a ${env:NAME} placeholder. Placeholders are resolved only in
// plugins.*.config values (whole or embedded), in the file and in the overlay (R24).
var EnvRefPattern = regexp.MustCompile(`\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}`)

var (
	// ErrEnvMissing is returned by ResolveEnv when a referenced variable is unset.
	ErrEnvMissing = errors.New("environment variable is not set")
	// ErrEnvForbidden is returned by ResolveEnv for a forbidden variable name.
	ErrEnvForbidden = errors.New("environment variable may not be referenced")
)

// forbiddenEnvPrefix protects the agent's own API credentials.
const forbiddenEnvPrefix = "CCF_API_AUTH_"

// EnvRefs returns the variable names referenced in s, in order of first appearance and
// deduplicated.
func EnvRefs(s string) []string {
	matches := EnvRefPattern.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// IsForbiddenEnvName reports whether a variable may never be referenced (CCF_API_AUTH_*,
// case-insensitive).
func IsForbiddenEnvName(name string) bool {
	return strings.HasPrefix(strings.ToUpper(name), forbiddenEnvPrefix)
}

// ResolveEnv returns a copy of c with ${env:NAME} placeholders in plugins.*.config values
// replaced by lookup(NAME). Nothing else is resolved. An unset variable yields an error
// wrapping ErrEnvMissing; a forbidden name yields an error wrapping ErrEnvForbidden. There is
// no escaping syntax in v1. Agent only: reports, redaction and digests use the unresolved
// config.
func ResolveEnv(c Config, lookup func(string) (string, bool)) (Config, error) {
	out := c.clone()
	for _, pluginName := range sortedKeys(out.Plugins) {
		p := out.Plugins[pluginName]
		if p == nil {
			continue
		}
		for _, key := range sortedKeys(p.Config) {
			value := p.Config[key]
			names := EnvRefs(value)
			if len(names) == 0 {
				continue
			}
			ptr := Pointer("plugins", pluginName, "config", key)
			for _, n := range names {
				if IsForbiddenEnvName(n) {
					return Config{}, fmt.Errorf("%w: ${env:%s} at %s", ErrEnvForbidden, n, ptr)
				}
			}
			var missing string
			resolved := EnvRefPattern.ReplaceAllStringFunc(value, func(ref string) string {
				n := EnvRefPattern.FindStringSubmatch(ref)[1]
				v, ok := lookup(n)
				if !ok && missing == "" {
					missing = n
				}
				return v
			})
			if missing != "" {
				return Config{}, fmt.Errorf("%w: ${env:%s} at %s", ErrEnvMissing, missing, ptr)
			}
			p.Config[key] = resolved
		}
	}
	return out, nil
}
