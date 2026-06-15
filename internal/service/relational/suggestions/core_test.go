package suggestions

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliance-framework/api/internal/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCanonicalLabelSetHashStable(t *testing.T) {
	got := CanonicalLabelSetHash(map[string]string{"repo": "API", "Env": "Prod"})
	require.Equal(t, "3839e61d314736aafb6a1e944edf2b75e8ed4d0bb8ff3d293194a5cc7bb70917", got)
	require.Equal(t, got, CanonicalLabelSetHash(map[string]string{"env": "Prod", "Repo": "API"}))
	require.NotEqual(t, got, CanonicalLabelSetHash(map[string]string{"env": "prod", "repo": "API"}))
}

func TestBuildLabelFilterCanonicalizeRoundTrip(t *testing.T) {
	labels := map[string]string{"env": "prod", "repo": "api"}
	filter := BuildLabelFilter(labels)
	got, ok := CanonicalizeFilter(filter)
	require.True(t, ok)
	require.Equal(t, labels, got)
}

func TestCanonicalizeFilterRefusesOrAndNotEquals(t *testing.T) {
	orFilter := labelfilter.Filter{Scope: &labelfilter.Scope{Query: &labelfilter.Query{
		Operator: "OR",
		Scopes: []labelfilter.Scope{
			{Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: "prod"}},
			{Condition: &labelfilter.Condition{Label: "env", Operator: "=", Value: "staging"}},
		},
	}}}
	_, ok := CanonicalizeFilter(orFilter)
	require.False(t, ok)

	notEqualFilter := labelfilter.Filter{Scope: &labelfilter.Scope{Condition: &labelfilter.Condition{
		Label: "env", Operator: "!=", Value: "prod",
	}}}
	_, ok = CanonicalizeFilter(notEqualFilter)
	require.False(t, ok)
}

func TestResolveSnapshot(t *testing.T) {
	controls := []string{"catalog-b:AC-2", "catalog-a:AC-1"}
	hashes := []string{"h2", "h1"}

	snapshot, err := ResolveSnapshot(Scope{}, controls, hashes)
	require.NoError(t, err)
	require.Equal(t, Snapshot{
		ControlKeys:    []string{"catalog-a:AC-1", "catalog-b:AC-2"},
		LabelSetHashes: []string{"h1", "h2"},
	}, snapshot)

	snapshot, err = ResolveSnapshot(Scope{ControlKeys: []string{"catalog-b:AC-2"}, LabelSetHashes: []string{"h1"}}, controls, hashes)
	require.NoError(t, err)
	require.Equal(t, []string{"catalog-b:AC-2"}, snapshot.ControlKeys)
	require.Equal(t, []string{"h1"}, snapshot.LabelSetHashes)

	_, err = ResolveSnapshot(Scope{ControlKeys: []string{"missing"}, LabelSetHashes: []string{"h3"}}, controls, hashes)
	var scopeErr *ScopeError
	require.True(t, errors.As(err, &scopeErr))
	require.Equal(t, []string{"missing"}, scopeErr.UnknownControlKeys)
	require.Equal(t, []string{"h3"}, scopeErr.UnknownLabelSetHashes)
}

func TestBuildGridAndPlannedCalls(t *testing.T) {
	snapshot := Snapshot{
		ControlKeys:    []string{"c1", "c2", "c3"},
		LabelSetHashes: []string{"l1", "l2", "l3", "l4", "l5"},
	}
	cfg := ChunkConfig{MaxControlsPerChunk: 2, MaxLabelSetsPerChunk: 2}
	require.Equal(t, 6, PlannedCalls(len(snapshot.ControlKeys), len(snapshot.LabelSetHashes), cfg))

	cells := BuildGrid(snapshot, cfg)
	require.Len(t, cells, 6)
	seen := map[string]int{}
	for _, cell := range cells {
		for _, control := range cell.ControlKeys {
			for _, labelSet := range cell.LabelSetHashes {
				seen[control+"|"+labelSet]++
			}
		}
	}
	require.Len(t, seen, len(snapshot.ControlKeys)*len(snapshot.LabelSetHashes))
	for _, count := range seen {
		require.Equal(t, 1, count)
	}
	require.Equal(t, 1, PlannedCalls(1, 1, ChunkConfig{}))
}

func TestValidateMappingsRules(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	labelHash := CanonicalLabelSetHash(map[string]string{"env": "prod"})
	otherHash := CanonicalLabelSetHash(map[string]string{"env": "stage"})
	sameSSPFilterID := uuid.New()
	globalFilterID := uuid.New()

	longReason := strings.Repeat("a", MaxReasoningLength+10)
	input := CellInput{
		Controls: []ControlInput{{ControlKey: controlKey}},
		LabelSets: []LabelSetInput{
			{Hash: labelHash, Labels: map[string]string{"env": "prod"}},
			{Hash: otherHash, Labels: map[string]string{"env": "stage"}},
		},
		SameSSPFilters: []VisibleFilterInput{{ID: sameSSPFilterID, Name: "prod", LabelSetHash: &labelHash}},
		VisibleFilters: []VisibleFilterInput{{ID: globalFilterID, Name: "global", LabelSetHash: &labelHash}},
	}

	result := ValidateRawMappings(input, []RawMapping{
		{ControlKey: "missing", LabelSetHash: labelHash, Action: MappingActionNewFilter, ProposedFilterName: "bad", Confidence: 0.5, Reasoning: "x"},
		{ControlKey: controlKey, LabelSetHash: "missing", Action: MappingActionNewFilter, ProposedFilterName: "bad", Confidence: 0.5, Reasoning: "x"},
		{ControlKey: controlKey, LabelSetHash: labelHash, Action: MappingActionNewFilter, ProposedFilterName: "bad", Confidence: 1.5, Reasoning: "x"},
		{ControlKey: controlKey, LabelSetHash: labelHash, Action: MappingActionNewFilter, ProposedFilterName: "bad", Confidence: 0.5, Reasoning: ""},
		{ControlKey: controlKey, LabelSetHash: labelHash, Action: MappingActionExtendFilter, TargetFilterID: globalFilterID.String(), Confidence: 0.4, Reasoning: longReason},
		{ControlKey: controlKey, LabelSetHash: labelHash, Action: MappingActionExtendFilter, TargetFilterID: sameSSPFilterID.String(), Confidence: 0.9, Reasoning: "better"},
		{ControlKey: controlKey, LabelSetHash: labelHash, Action: MappingActionNewFilter, ProposedFilterName: "lower", Confidence: 0.1, Reasoning: "dedupe"},
		{ControlKey: controlKey, LabelSetHash: otherHash, Action: MappingActionNewFilter, Confidence: 0.8, Reasoning: "fallback"},
	})

	require.Equal(t, 1, result.Counts["rejected_unknown_control"])
	require.Equal(t, 1, result.Counts["rejected_unknown_label_set"])
	require.Equal(t, 1, result.Counts["rejected_confidence_out_of_range"])
	require.Equal(t, 1, result.Counts["rejected_empty_reasoning"])
	require.Equal(t, 1, result.Counts["downgraded_extend_to_new"])
	require.Equal(t, 2, result.Counts["deduped_within_cell"])
	require.Equal(t, 2, result.Counts["fallback_name"])
	require.Len(t, result.Mappings, 2)
	require.Equal(t, MappingActionExtendFilter, result.Mappings[0].Action)
	require.Equal(t, sameSSPFilterID, *result.Mappings[0].TargetFilterID)
	require.Equal(t, "env=stage", result.Mappings[1].ProposedFilterName)
}

func TestValidateMappingsControlCap(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	input := CellInput{Controls: []ControlInput{{ControlKey: controlKey}}}
	raw := make([]RawMapping, 0, MaxMappingsPerControlPerCell+1)
	for i := 0; i < MaxMappingsPerControlPerCell+1; i++ {
		hash := CanonicalLabelSetHash(map[string]string{"n": string(rune('a' + i))})
		input.LabelSets = append(input.LabelSets, LabelSetInput{Hash: hash, Labels: map[string]string{"n": string(rune('a' + i))}})
		raw = append(raw, RawMapping{ControlKey: controlKey, LabelSetHash: hash, Action: MappingActionNewFilter, ProposedFilterName: "x", Confidence: float64(i) / 100, Reasoning: "x"})
	}
	result := ValidateRawMappings(input, raw)
	require.Len(t, result.Mappings, MaxMappingsPerControlPerCell)
	require.Equal(t, 1, result.Counts["dropped_control_cap"])
}

func TestPromptGolden(t *testing.T) {
	input := GatheredInput{
		SystemContext: SystemContextInput{
			SystemName:  "Payments API",
			Description: "Processes card payments.",
			Components:  []SystemComponentInput{{Title: "payments-api", Type: "service", Purpose: "payment processing", Description: "Go API"}},
		},
		Controls:       []ControlInput{{ControlKey: "11111111-1111-1111-1111-111111111111:AC-1", Title: "Policy", ImplementationText: "Uses payments-api."}},
		LabelSets:      []LabelSetInput{{Hash: "hash1", Labels: map[string]string{"repo": "payments-api"}, EvidenceCount: 2, SampleTitles: []string{"scan"}}},
		LabelKeyDocs:   []LabelKeyDocInput{{Key: "repo", Description: "Repository name"}},
		SameSSPFilters: []VisibleFilterInput{{ID: uuid.MustParse("22222222-2222-2222-2222-222222222222"), Name: "payments-api"}},
	}
	gotPrompt, err := RenderPrompt(input)
	require.NoError(t, err)
	got := SystemPrompt + "\n---USER---\n" + gotPrompt
	path := filepath.Join("testdata", "prompt_"+PromptVersion+".golden")
	expected, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, strings.TrimSuffix(string(expected), "\n"), got)
}
