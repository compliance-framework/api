package agentconfig

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Diff operations.
const (
	DiffOpAdd     = "add"
	DiffOpRemove  = "remove"
	DiffOpReplace = "replace"
)

// DiffEntry is one difference between two JSON documents. Path is an RFC 6901 pointer.
type DiffEntry struct {
	Path string          `json:"path"`
	Op   string          `json:"op"` // add | remove | replace
	From json.RawMessage `json:"from,omitempty" swaggertype:"object"`
	To   json.RawMessage `json:"to,omitempty" swaggertype:"object"`
}

// DiffJSON compares two JSON documents. Objects recurse; arrays and scalars are leaves. A key
// present on one side only is an add or a remove of the whole value; a value that differs
// (including a type change) is a replace. Empty input is treated as null. The result is
// sorted by Path.
func DiffJSON(a, b []byte) ([]DiffEntry, error) {
	va, err := decodeAny(a)
	if err != nil {
		return nil, fmt.Errorf("diff: decode first document: %w", err)
	}
	vb, err := decodeAny(b)
	if err != nil {
		return nil, fmt.Errorf("diff: decode second document: %w", err)
	}
	var out []DiffEntry
	if err := diffValues("", va, vb, true, true, &out); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(x, y DiffEntry) int { return strings.Compare(x.Path, y.Path) })
	return out, nil
}

func diffValues(path string, a, b any, hasA, hasB bool, out *[]DiffEntry) error {
	switch {
	case hasA && !hasB:
		from, err := encodeCanonical(a)
		if err != nil {
			return err
		}
		*out = append(*out, DiffEntry{Path: path, Op: DiffOpRemove, From: from})
		return nil
	case !hasA && hasB:
		to, err := encodeCanonical(b)
		if err != nil {
			return err
		}
		*out = append(*out, DiffEntry{Path: path, Op: DiffOpAdd, To: to})
		return nil
	}
	objA, okA := a.(map[string]any)
	objB, okB := b.(map[string]any)
	if okA && okB {
		for _, k := range unionKeys(objA, objB) {
			va, inA := objA[k]
			vb, inB := objB[k]
			if err := diffValues(appendPointer(path, k), va, vb, inA, inB, out); err != nil {
				return err
			}
		}
		return nil
	}
	if jsonEqual(a, b) {
		return nil
	}
	from, err := encodeCanonical(a)
	if err != nil {
		return err
	}
	to, err := encodeCanonical(b)
	if err != nil {
		return err
	}
	*out = append(*out, DiffEntry{Path: path, Op: DiffOpReplace, From: from, To: to})
	return nil
}

func unionKeys(a, b map[string]any) []string {
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
