package agentconfig

import (
	"encoding/json"
	"slices"
	"strings"
)

// PolicyOnlyChange reports whether going from overlay current to overlay next touches only
// what agent:configure-policy may change (D18, R22). bases are the reported bases of the
// validation set; an empty list means a single zero Config (conservative).
//
//  1. Every changed leaf must be under /policy_bundles or be exactly /plugins/<p>/policies.
//     (Leaves are computed with objects expanded, so adding a plugins.<p>.policies key for
//     the first time reports /plugins/<p>/policies, not /plugins.)
//  2. For every such p and every base B, with F = Merge(B, current) and T = Merge(B, next):
//     F and T have the same set of plugins (an empty "plugins.x: {}" has no leaves but
//     still adds a plugin), p must exist in F whenever it exists in T, and with
//     f = F.p.policies and t = T.p.policies either
//     (a) nonInline(f) == nonInline(t) as ordered sequences (pure inline add/remove), or
//     (b) len(f) == len(t) and at every index f[i] == t[i], both are inline:, or a source S
//     is swapped with inline:B where the bundle B extends S (either direction).
//
// A revision mixing a swap with an add/remove elsewhere in the same list is rejected; split
// it into two saves. Any decode or merge failure yields false.
func PolicyOnlyChange(current, next json.RawMessage, bases []Config) bool {
	cur, err := decodeAny(current)
	if err != nil {
		return false
	}
	nxt, err := decodeAny(next)
	if err != nil {
		return false
	}
	var paths []string
	leafDiffPaths("", cur, nxt, cur != nil, nxt != nil, &paths)

	var plugins []string
	for _, p := range paths {
		if p == "/policy_bundles" || strings.HasPrefix(p, "/policy_bundles/") {
			continue
		}
		segs := SplitPointer(p)
		if len(segs) == 3 && segs[0] == "plugins" && segs[2] == "policies" {
			if !slices.Contains(plugins, segs[1]) {
				plugins = append(plugins, segs[1])
			}
			continue
		}
		return false
	}
	if len(bases) == 0 {
		bases = []Config{{}}
	}
	for _, base := range bases {
		from, err := Merge(base, current)
		if err != nil {
			return false
		}
		to, err := Merge(base, next)
		if err != nil {
			return false
		}
		// The leaf diff above expands objects, so an empty plugin object ("plugins.x: {}")
		// has no leaves yet still adds a plugin. The set of plugins must not change.
		if !slices.Equal(sortedKeys(from.Plugins), sortedKeys(to.Plugins)) {
			return false
		}
		for _, name := range plugins {
			tp := to.Plugins[name]
			fp := from.Plugins[name]
			if tp == nil {
				// The plugin disappears; that is not a policies-only change.
				if fp != nil {
					return false
				}
				continue
			}
			if fp == nil {
				return false
			}
			if !policiesChangeAllowed(fp.Policies, tp.Policies, from.PolicyBundles, to.PolicyBundles) {
				return false
			}
		}
	}
	return true
}

func policiesChangeAllowed(f, t []string, fromBundles, toBundles map[string]*PolicyBundle) bool {
	if slices.Equal(nonInline(f), nonInline(t)) {
		return true
	}
	if len(f) != len(t) {
		return false
	}
	for i := range f {
		a, b := f[i], t[i]
		switch {
		case a == b:
		case IsInlineSource(a) && IsInlineSource(b):
		case !IsInlineSource(a) && IsInlineSource(b) && bundleExtends(toBundles, b, a):
		case IsInlineSource(a) && !IsInlineSource(b) && bundleExtends(fromBundles, a, b):
		default:
			return false
		}
	}
	return true
}

// bundleExtends reports whether the bundle named by inline entry extends source.
func bundleExtends(bundles map[string]*PolicyBundle, inlineEntry, source string) bool {
	name, ok := InlineBundleName(inlineEntry)
	if !ok {
		return false
	}
	b := bundles[name]
	return b != nil && b.Extends != nil && *b.Extends == source
}

func nonInline(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !IsInlineSource(e) {
			out = append(out, e)
		}
	}
	return out
}
