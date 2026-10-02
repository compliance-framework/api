package agentconfig

import (
	"path"
	"strings"
)

// Normalize applies the remote_config defaults (R29):
//   - Mode "" becomes apply_safe with auth, off without; no auth always forces off;
//   - PollInterval "" becomes "60s";
//   - nil TrustedSources / OverridableConfigFlags become [];
//   - AllowLocalSources stays false unless set.
func (rc RemoteConfig) Normalize(hasAuth bool) RemoteConfig {
	out := rc
	switch {
	case !hasAuth:
		out.Mode = ModeOff
	case out.Mode == "":
		out.Mode = ModeApplySafe
	}
	if out.PollInterval == "" {
		out.PollInterval = "60s" // DefaultPollInterval, in the form operators write
	}
	out.TrustedSources = cloneStrings(rc.TrustedSources)
	if out.TrustedSources == nil {
		out.TrustedSources = []string{}
	}
	out.OverridableConfigFlags = cloneStrings(rc.OverridableConfigFlags)
	if out.OverridableConfigFlags == nil {
		out.OverridableConfigFlags = []string{}
	}
	return out
}

// EffectiveRemoteConfig returns the normalized remote_config block of c, using c.API to
// decide whether the agent has credentials.
func (c Config) EffectiveRemoteConfig() RemoteConfig {
	var rc RemoteConfig
	if c.RemoteConfig != nil {
		rc = *c.RemoteConfig
	}
	return rc.Normalize(c.API.HasAuth())
}

// MatchTrustedSource reports whether source matches one of rc.TrustedSources using
// path.Match semantics: case-sensitive, and '*' does not cross '/'.
func MatchTrustedSource(rc RemoteConfig, source string) bool {
	for _, pattern := range rc.TrustedSources {
		if ok, err := path.Match(pattern, source); err == nil && ok {
			return true
		}
	}
	return false
}

// MatchOverridableConfigFlag reports whether plugins.<plugin>.config.<key> may be changed
// remotely. An entry containing ':' is "<plugin-glob>:<key-glob>" (split at the first ':');
// otherwise it is "<key-glob>" for any plugin. Matching is path.Match, case-sensitive; base
// keys are lowercased by viper (R28).
func MatchOverridableConfigFlag(rc RemoteConfig, plugin, key string) bool {
	for _, entry := range rc.OverridableConfigFlags {
		pluginGlob, keyGlob, scoped := strings.Cut(entry, ":")
		if !scoped {
			keyGlob = entry
			pluginGlob = "*"
		}
		pluginOK, err := path.Match(pluginGlob, plugin)
		if err != nil || !pluginOK {
			continue
		}
		if keyOK, err := path.Match(keyGlob, key); err == nil && keyOK {
			return true
		}
	}
	return false
}
