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
//  3. For every base B, a new or changed policy_bundles.<b>.extends in T (absent from F, or
//     with a different value there) must name a source B already uses (usedSources: plugin
//     sources, non-inline policy entries and extends values), or be the source S that step
//     2(b) swapped with inline:<b> at the same index (R58). Anything else introduces a new
//     vendor source and needs agent:configure. Removing extends, or leaving it unchanged, is
//     fine. This also applies when the diff touches only /policy_bundles.
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
		name, ok := policyLeaf(p)
		if !ok {
			return false
		}
		if name != "" && !slices.Contains(plugins, name) {
			plugins = append(plugins, name)
		}
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
		// swapped maps a bundle name to the source S it replaced through an accepted R22
		// swap (S -> inline:<b>) in this base.
		swapped := map[string]string{}
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
			if !policiesChangeAllowed(fp.Policies, tp.Policies, from.PolicyBundles, to.PolicyBundles, swapped) {
				return false
			}
		}
		if !extendsChangeAllowed(from.PolicyBundles, to.PolicyBundles, usedSources(base), swapped) {
			return false
		}
	}
	return true
}

// FirstNonPolicyPath returns the first changed leaf between two overlays that is outside
// what agent:configure-policy may touch (step 1 of PolicyOnlyChange), or "" when every
// changed leaf is a policy path. It is for audit/diagnostics only; PolicyOnlyChange stays
// the authority (it can also refuse a policy-path change, e.g. a new extends source).
func FirstNonPolicyPath(current, next json.RawMessage) string {
	cur, err := decodeAny(current)
	if err != nil {
		return ""
	}
	nxt, err := decodeAny(next)
	if err != nil {
		return ""
	}
	var paths []string
	leafDiffPaths("", cur, nxt, cur != nil, nxt != nil, &paths)
	for _, p := range paths {
		if _, ok := policyLeaf(p); !ok {
			return p
		}
	}
	return ""
}

// policyLeaf reports whether a changed leaf is one configure-policy may change: anything
// under /policy_bundles, or exactly /plugins/<p>/policies (then plugin is <p>).
func policyLeaf(p string) (plugin string, ok bool) {
	if p == "/policy_bundles" || strings.HasPrefix(p, "/policy_bundles/") {
		return "", true
	}
	segs := SplitPointer(p)
	if len(segs) == 3 && segs[0] == "plugins" && segs[2] == "policies" {
		return segs[1], true
	}
	return "", false
}

// policiesChangeAllowed applies step 2 to one plugin's policy list. Every S -> inline:<b>
// swap it accepts is recorded in swapped (bundle name -> S).
func policiesChangeAllowed(f, t []string, fromBundles, toBundles map[string]*PolicyBundle, swapped map[string]string) bool {
	if slices.Equal(nonInline(f), nonInline(t)) {
		return true
	}
	if len(f) != len(t) {
		return false
	}
	accepted := map[string]string{}
	for i := range f {
		a, b := f[i], t[i]
		switch {
		case a == b:
		case IsInlineSource(a) && IsInlineSource(b):
		case !IsInlineSource(a) && IsInlineSource(b) && bundleExtends(toBundles, b, a):
			name, _ := InlineBundleName(b)
			accepted[name] = a
		case IsInlineSource(a) && !IsInlineSource(b) && bundleExtends(fromBundles, a, b):
		default:
			return false
		}
	}
	for name, src := range accepted {
		swapped[name] = src
	}
	return true
}

// extendsChangeAllowed applies step 3 (R58): a new or changed extends must name a source
// the base already uses, or the source the bundle replaced through an accepted swap.
func extendsChangeAllowed(fromBundles, toBundles map[string]*PolicyBundle, used map[string]bool, swapped map[string]string) bool {
	for name, tb := range toBundles {
		if tb == nil || tb.Extends == nil {
			continue
		}
		fb := fromBundles[name]
		if fb != nil && fb.Extends != nil && *fb.Extends == *tb.Extends {
			continue
		}
		if src, ok := swapped[name]; (ok && src == *tb.Extends) || used[*tb.Extends] {
			continue
		}
		return false
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
