package suggestions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
)

const (
	DefaultMaxControlsPerChunk          = 40
	DefaultMaxLabelSetsPerChunk         = 200
	DefaultMaxSuggestionsPerRun         = 500
	MaxMappingsPerControlPerCell        = 10
	MaxReasoningLength                  = 2000
	ReasoningTruncatedMarker            = "\n[truncated]"
	DashboardSuggestionStatusPending    = "pending"
	DashboardSuggestionStatusAccepted   = "accepted"
	DashboardSuggestionStatusRejected   = "rejected"
	DashboardSuggestionStatusSuperseded = "superseded"
)

type ChunkConfig struct {
	MaxControlsPerChunk  int
	MaxLabelSetsPerChunk int
}

type Scope struct {
	ControlKeys    []string
	LabelSetHashes []string
	// LabelFilter, when set, restricts which evidence (and therefore which
	// canonical label sets) feed the run. Empty/nil means all evidence.
	LabelFilter *labelfilter.Filter
}

type Snapshot struct {
	ControlKeys    []string `json:"controlKeys"`
	LabelSetHashes []string `json:"labelSetHashes"`
}

type GridCell struct {
	CellIndex      int
	ControlKeys    []string
	LabelSetHashes []string
}

type ScopeError struct {
	UnknownControlKeys    []string
	UnknownLabelSetHashes []string
}

func (e *ScopeError) Error() string {
	parts := make([]string, 0, 2)
	if len(e.UnknownControlKeys) > 0 {
		parts = append(parts, "unknown control keys: "+strings.Join(e.UnknownControlKeys, ", "))
	}
	if len(e.UnknownLabelSetHashes) > 0 {
		parts = append(parts, "unknown label-set hashes: "+strings.Join(e.UnknownLabelSetHashes, ", "))
	}
	if len(parts) == 0 {
		return "invalid suggestion scope"
	}
	return strings.Join(parts, "; ")
}

func ResolveSnapshot(scope Scope, allControlKeys []string, allLabelSetHashes []string) (Snapshot, error) {
	controls := append([]string(nil), allControlKeys...)
	labelSets := append([]string(nil), allLabelSetHashes...)
	sort.Strings(controls)
	sort.Strings(labelSets)
	labelSet := stringSet(labelSets)
	// Control keys fold case (the control_id casing invariant: match via UPPER),
	// resolving requested keys back to the canonical stored keys. Label-set
	// hashes are exact hex and stay case-sensitive.
	selectedControls, unknownControls := selectControlDimension(scope.ControlKeys, controls)
	selectedLabelSets, unknownLabelSets := selectDimension(scope.LabelSetHashes, labelSets, labelSet)
	if len(unknownControls) > 0 || len(unknownLabelSets) > 0 {
		return Snapshot{}, &ScopeError{UnknownControlKeys: unknownControls, UnknownLabelSetHashes: unknownLabelSets}
	}
	return Snapshot{ControlKeys: selectedControls, LabelSetHashes: selectedLabelSets}, nil
}

// selectControlDimension resolves requested control keys against the canonical
// keys case-insensitively, returning the canonical keys (so the snapshot stays
// catalog-canonical). Empty request selects all.
func selectControlDimension(requested []string, all []string) ([]string, []string) {
	if len(requested) == 0 {
		return append([]string(nil), all...), nil
	}
	canonical := make(map[string]string, len(all))
	for _, key := range all {
		canonical[strings.ToUpper(key)] = key
	}
	selectedSet := map[string]struct{}{}
	unknown := make([]string, 0)
	for _, value := range requested {
		canon, ok := canonical[strings.ToUpper(strings.TrimSpace(value))]
		if !ok {
			unknown = append(unknown, value)
			continue
		}
		selectedSet[canon] = struct{}{}
	}
	sort.Strings(unknown)
	selected := make([]string, 0, len(selectedSet))
	for _, key := range all {
		if _, ok := selectedSet[key]; ok {
			selected = append(selected, key)
		}
	}
	return selected, unknown
}

func CanonicalLabelSetHash(labels map[string]string) string {
	normalized, ok := NormalizeLabelSet(labels)
	lines := canonicalLabelLines(normalized)
	if !ok {
		lines = conflictingLabelLines(labels)
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

func NormalizeLabelSet(labels map[string]string) (map[string]string, bool) {
	normalized := make(map[string]string, len(labels))
	for key, value := range labels {
		lowerKey := strings.ToLower(key)
		existing, seen := normalized[lowerKey]
		if seen && existing != value {
			return nil, false
		}
		normalized[lowerKey] = value
	}
	return normalized, true
}

func BuildLabelFilter(labels map[string]string) labelfilter.Filter {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	scopes := make([]labelfilter.Scope, 0, len(keys))
	for _, key := range keys {
		scopes = append(scopes, labelfilter.Scope{
			Condition: &labelfilter.Condition{
				Label:    key,
				Operator: "=",
				Value:    labels[key],
			},
		})
	}

	if len(scopes) == 1 {
		return labelfilter.Filter{Scope: &scopes[0]}
	}

	return labelfilter.Filter{
		Scope: &labelfilter.Scope{
			Query: &labelfilter.Query{
				Operator: "AND",
				Scopes:   scopes,
			},
		},
	}
}

func CanonicalizeFilter(filter labelfilter.Filter) (map[string]string, bool) {
	if filter.Scope == nil {
		return map[string]string{}, true
	}
	labels := map[string]string{}
	if !canonicalizeScope(*filter.Scope, labels) {
		return nil, false
	}
	return labels, true
}

func canonicalizeScope(scope labelfilter.Scope, labels map[string]string) bool {
	if scope.Condition != nil {
		condition := scope.Condition
		if condition.Operator != "=" {
			return false
		}
		key := strings.ToLower(condition.Label)
		existing, seen := labels[key]
		if seen && existing != condition.Value {
			return false
		}
		if seen {
			return true
		}
		labels[key] = condition.Value
		return true
	}
	query := scope.Query
	if query == nil || !strings.EqualFold(query.Operator, "AND") {
		return false
	}
	for _, child := range query.Scopes {
		if !canonicalizeScope(child, labels) {
			return false
		}
	}
	return true
}

func canonicalLabelLines(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, fmt.Sprintf("%s=%s", key, labels[key]))
	}
	return lines
}

func conflictingLabelLines(labels map[string]string) []string {
	lines := make([]string, 0, len(labels))
	for key, value := range labels {
		lines = append(lines, fmt.Sprintf("%s=%s", strings.ToLower(key), value))
	}
	sort.Strings(lines)
	return lines
}

func PlannedCalls(controlCount, labelSetCount int, cfg ChunkConfig) int {
	cfg = normalizeChunkConfig(cfg)
	if controlCount == 0 || labelSetCount == 0 {
		return 0
	}
	return int(math.Ceil(float64(controlCount)/float64(cfg.MaxControlsPerChunk))) *
		int(math.Ceil(float64(labelSetCount)/float64(cfg.MaxLabelSetsPerChunk)))
}

func BuildGrid(snapshot Snapshot, cfg ChunkConfig) []GridCell {
	cfg = normalizeChunkConfig(cfg)
	cells := make([]GridCell, 0, PlannedCalls(len(snapshot.ControlKeys), len(snapshot.LabelSetHashes), cfg))
	cellIndex := 0
	for cStart := 0; cStart < len(snapshot.ControlKeys); cStart += cfg.MaxControlsPerChunk {
		cEnd := min(cStart+cfg.MaxControlsPerChunk, len(snapshot.ControlKeys))
		for lStart := 0; lStart < len(snapshot.LabelSetHashes); lStart += cfg.MaxLabelSetsPerChunk {
			lEnd := min(lStart+cfg.MaxLabelSetsPerChunk, len(snapshot.LabelSetHashes))
			cells = append(cells, GridCell{
				CellIndex:      cellIndex,
				ControlKeys:    append([]string(nil), snapshot.ControlKeys[cStart:cEnd]...),
				LabelSetHashes: append([]string(nil), snapshot.LabelSetHashes[lStart:lEnd]...),
			})
			cellIndex++
		}
	}
	return cells
}

func normalizeChunkConfig(cfg ChunkConfig) ChunkConfig {
	if cfg.MaxControlsPerChunk <= 0 {
		cfg.MaxControlsPerChunk = DefaultMaxControlsPerChunk
	}
	if cfg.MaxLabelSetsPerChunk <= 0 {
		cfg.MaxLabelSetsPerChunk = DefaultMaxLabelSetsPerChunk
	}
	return cfg
}
