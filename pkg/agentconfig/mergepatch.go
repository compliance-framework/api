package agentconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// MergePatch applies an RFC 7396 JSON merge patch. target may be nil/empty (treated as
// null). A non-object patch replaces the target. Objects merge recursively, null deletes a
// key and arrays replace wholesale. Numbers are preserved exactly. The result is canonical
// JSON (sorted keys, no HTML escaping).
func MergePatch(target, patch []byte) ([]byte, error) {
	t, err := decodeAny(target)
	if err != nil {
		return nil, fmt.Errorf("merge patch: decode target: %w", err)
	}
	p, err := decodeAny(patch)
	if err != nil {
		return nil, fmt.Errorf("merge patch: decode patch: %w", err)
	}
	return encodeCanonical(mergeValue(t, p))
}

// mergeValue implements the RFC 7396 MergePatch pseudo-code on decoded values.
func mergeValue(target, patch any) any {
	patchObj, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	targetObj, ok := target.(map[string]any)
	if !ok {
		targetObj = map[string]any{}
	}
	for k, v := range patchObj {
		if v == nil {
			delete(targetObj, k)
			continue
		}
		targetObj[k] = mergeValue(targetObj[k], v)
	}
	return targetObj
}

// StripLocked returns the overlay without the top-level LockedKeys and the sorted list of
// removed keys. A nil/empty/"null" overlay is returned as "{}". A non-object overlay is an
// error.
func StripLocked(overlay []byte) (stripped []byte, removed []string, err error) {
	v, err := decodeAny(overlay)
	if err != nil {
		return nil, nil, fmt.Errorf("strip locked keys: %w", err)
	}
	if v == nil {
		return []byte("{}"), nil, nil
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, nil, errors.New("strip locked keys: overlay must be a JSON object")
	}
	for _, k := range LockedKeys {
		if _, present := obj[k]; present {
			delete(obj, k)
			removed = append(removed, k)
		}
	}
	slices.Sort(removed)
	out, err := encodeCanonical(obj)
	if err != nil {
		return nil, nil, err
	}
	return out, removed, nil
}

// Merge computes the effective config: StripLocked(overlay), then MergePatch onto
// json.Marshal(base), then a non-strict decode into Config (so fields a newer base carries
// survive). Locked keys always come from base, as defence in depth (R23).
//
// Merge does no env resolution, applies no defaults and does no validation. It errors when
// the overlay is not an object or the merged document does not fit the Config types (for
// example a number where a string map value is expected); ValidateOverlay reports those
// problems with pointers.
func Merge(base Config, overlay json.RawMessage) (Config, error) {
	stripped, _, err := StripLocked(overlay)
	if err != nil {
		return Config{}, err
	}
	b := base.clone()
	baseJSON, err := json.Marshal(b)
	if err != nil {
		return Config{}, fmt.Errorf("merge: encode base: %w", err)
	}
	merged, err := MergePatch(baseJSON, stripped)
	if err != nil {
		return Config{}, err
	}
	out, err := decodeConfig(merged)
	if err != nil {
		return Config{}, fmt.Errorf("merge: decode effective config: %w", err)
	}
	out.API = b.API
	out.Daemon = b.Daemon
	out.RemoteConfig = b.RemoteConfig
	return out, nil
}
