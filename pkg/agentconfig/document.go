package agentconfig

import (
	"encoding/json"
	"fmt"
)

// OverlayBundles extracts the policy bundles an overlay defines, for the Rego checks: only
// non-null bundles, and only their non-null string modules (a null module is a deletion).
// Non-object or wrongly-typed parts are skipped; ValidateOverlay reports them.
func OverlayBundles(overlay json.RawMessage) (map[string]*PolicyBundle, error) {
	v, err := decodeAny(overlay)
	if err != nil {
		return nil, fmt.Errorf("overlay bundles: %w", err)
	}
	obj, _ := v.(map[string]any)
	bundles, _ := obj["policy_bundles"].(map[string]any)
	out := map[string]*PolicyBundle{}
	for name, raw := range bundles {
		b, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		pb := &PolicyBundle{}
		if ext, ok := b["extends"].(string); ok {
			pb.Extends = &ext
		}
		if modules, ok := b["modules"].(map[string]any); ok {
			for p, src := range modules {
				if s, ok := src.(string); ok {
					if pb.Modules == nil {
						pb.Modules = map[string]string{}
					}
					pb.Modules[p] = s
				}
			}
		}
		if del, ok := b["delete"].([]any); ok {
			for _, d := range del {
				if s, ok := d.(string); ok {
					pb.Delete = append(pb.Delete, s)
				}
			}
		}
		if data, ok := b["data"].(map[string]any); ok {
			pb.Data = data
		}
		out[name] = pb
	}
	return out, nil
}

// RedactDocument re-applies the server-side part of Redact to a reported config document
// (base or effective) WITHOUT decoding it into Config, so fields a newer agent sends are
// preserved (R51). It removes api.auth.client_secret and masks key-name matches under
// plugins.*.config, plugins.*.policy_data and policy_bundles.*.data (env placeholders are
// kept). It cannot know the agent's env-sourced pointers (R55), so it is best effort; on an
// agent-redacted document it is a no-op. changed reports whether anything was altered. The
// input must be a JSON object.
func RedactDocument(doc json.RawMessage) (out json.RawMessage, changed bool, err error) {
	v, err := decodeAny(doc)
	if err != nil {
		return nil, false, fmt.Errorf("redact document: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, false, fmt.Errorf("redact document: must be a JSON object")
	}
	before, err := encodeCanonical(obj)
	if err != nil {
		return nil, false, err
	}

	var o redactOpts
	if api, ok := obj["api"].(map[string]any); ok {
		if auth, ok := api["auth"].(map[string]any); ok {
			delete(auth, "client_secret")
		}
	}
	if plugins, ok := obj["plugins"].(map[string]any); ok {
		for name, raw := range plugins {
			p, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if cfg, ok := p["config"].(map[string]any); ok {
				p["config"] = o.redactMap(Pointer("plugins", name, "config"), cfg)
			}
			if data, ok := p["policy_data"].(map[string]any); ok {
				p["policy_data"] = o.redactMap(Pointer("plugins", name, "policy_data"), data)
			}
		}
	}
	if bundles, ok := obj["policy_bundles"].(map[string]any); ok {
		for name, raw := range bundles {
			b, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if data, ok := b["data"].(map[string]any); ok {
				b["data"] = o.redactMap(Pointer("policy_bundles", name, "data"), data)
			}
		}
	}

	after, err := encodeCanonical(obj)
	if err != nil {
		return nil, false, err
	}
	return after, string(before) != string(after), nil
}
