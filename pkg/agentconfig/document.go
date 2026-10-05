package agentconfig

import (
	"encoding/json"
	"fmt"
)

// RedactDocument re-applies Redact's rules to a reported config document (base or
// effective) WITHOUT decoding it into Config, so fields a newer agent sends are preserved
// (R51). It removes api.auth.client_secret, masks api.url, plugins.*.source and
// plugins.*.policies entries when they hold a secret by content, and masks plugins.*.config
// and plugins.*.policy_data exactly as Redact does (key names, content and placeholder
// rules). It cannot know the agent's env-sourced pointers (R55), so it is best
// effort; on a document Redact produced with the same rules it is a no-op. changed reports
// whether anything was altered. The input must be a JSON object.
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
		if u, ok := api["url"].(string); ok && containsSecretValue(u) {
			api["url"] = MaskedValue
		}
	}
	if plugins, ok := obj["plugins"].(map[string]any); ok {
		for name, raw := range plugins {
			p, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if src, ok := p["source"].(string); ok {
				p["source"] = maskSecretText(src)
			}
			if policies, ok := p["policies"].([]any); ok {
				for i, e := range policies {
					if entry, ok := e.(string); ok {
						policies[i] = maskSecretText(entry)
					}
				}
			}
			if cfg, ok := p["config"].(map[string]any); ok {
				p["config"] = o.redactMap(Pointer("plugins", name, "config"), cfg)
			}
			if data, ok := p["policy_data"].(map[string]any); ok {
				p["policy_data"] = o.redactMap(Pointer("plugins", name, "policy_data"), data)
			}
		}
	}
	after, err := encodeCanonical(obj)
	if err != nil {
		return nil, false, err
	}
	return after, string(before) != string(after), nil
}
