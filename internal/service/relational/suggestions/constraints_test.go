package suggestions

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func strptr(s string) *string { return &s }

func TestValidateMappingsMandatoryLabelsInjectAndReject(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	prodLabels := map[string]string{"env": "prod", "service": "api"}
	stageLabels := map[string]string{"env": "stage", "service": "api"}
	prodHash := CanonicalLabelSetHash(prodLabels)
	stageHash := CanonicalLabelSetHash(stageLabels)

	input := CellInput{
		Controls: []ControlInput{{ControlKey: controlKey}},
		LabelSets: []LabelSetInput{
			{Hash: prodHash, Labels: prodLabels},
			{Hash: stageHash, Labels: stageLabels},
		},
		Constraints: Constraints{
			MandatoryLabels: []LabelSelector{{Key: "env", Value: strptr("prod")}},
		}.Normalize(),
	}

	result := ValidateRawMappings(input, []RawMapping{
		{ControlKey: controlKey, LabelSetHash: prodHash, Action: MappingActionNewFilter, Confidence: 0.9, Reasoning: "prod", ProposedFilterLabels: map[string]string{"service": "api"}},
		{ControlKey: controlKey, LabelSetHash: stageHash, Action: MappingActionNewFilter, Confidence: 0.9, Reasoning: "stage", ProposedFilterLabels: map[string]string{"service": "api"}},
	})

	// The stage mapping is rejected (evidence has env=stage, not prod); the prod
	// mapping keeps its labels and gets the mandatory env=prod injected.
	require.Equal(t, 1, result.Counts["rejected_missing_mandatory_label"])
	require.Len(t, result.Mappings, 1)
	require.Equal(t, map[string]string{"service": "api", "env": "prod"}, result.Mappings[0].ProposedFilterLabelSet)
}

func TestValidateMappingsMandatoryKeyOnlySelector(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	labels := map[string]string{"env": "prod", "service": "api"}
	hash := CanonicalLabelSetHash(labels)

	input := CellInput{
		Controls:  []ControlInput{{ControlKey: controlKey}},
		LabelSets: []LabelSetInput{{Hash: hash, Labels: labels}},
		Constraints: Constraints{
			MandatoryLabels: []LabelSelector{{Key: "env"}}, // any value
		}.Normalize(),
	}

	result := ValidateRawMappings(input, []RawMapping{
		{ControlKey: controlKey, LabelSetHash: hash, Action: MappingActionNewFilter, Confidence: 0.9, Reasoning: "x", ProposedFilterLabels: map[string]string{"service": "api"}},
	})

	require.Len(t, result.Mappings, 1)
	require.Equal(t, "prod", result.Mappings[0].ProposedFilterLabelSet["env"])
}

func TestValidateMappingsExcludedLabelsStripped(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	labels := map[string]string{"env": "prod", "service": "api"}
	hash := CanonicalLabelSetHash(labels)

	input := CellInput{
		Controls:  []ControlInput{{ControlKey: controlKey}},
		LabelSets: []LabelSetInput{{Hash: hash, Labels: labels}},
		Constraints: Constraints{
			ExcludedLabels: []LabelSelector{{Key: "service"}},
		}.Normalize(),
	}

	result := ValidateRawMappings(input, []RawMapping{
		{ControlKey: controlKey, LabelSetHash: hash, Action: MappingActionNewFilter, Confidence: 0.9, Reasoning: "x", ProposedFilterLabels: map[string]string{"env": "prod", "service": "api"}},
	})

	require.Equal(t, 1, result.Counts["dropped_excluded_filter_labels"])
	require.Len(t, result.Mappings, 1)
	require.Equal(t, map[string]string{"env": "prod"}, result.Mappings[0].ProposedFilterLabelSet)
}

func TestValidateMappingsExcludedEmptiesRejected(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	labels := map[string]string{"service": "api"}
	hash := CanonicalLabelSetHash(labels)

	input := CellInput{
		Controls:  []ControlInput{{ControlKey: controlKey}},
		LabelSets: []LabelSetInput{{Hash: hash, Labels: labels}},
		Constraints: Constraints{
			ExcludedLabels: []LabelSelector{{Key: "service"}},
		}.Normalize(),
	}

	result := ValidateRawMappings(input, []RawMapping{
		{ControlKey: controlKey, LabelSetHash: hash, Action: MappingActionNewFilter, Confidence: 0.9, Reasoning: "x", ProposedFilterLabels: map[string]string{"service": "api"}},
	})

	require.Equal(t, 1, result.Counts["rejected_excluded_emptied"])
	require.Empty(t, result.Mappings)
}

func TestValidateMappingsOnlyActionFiltersNewFilters(t *testing.T) {
	controlKey := ControlKey(uuid.New(), "AC-1")
	labels := map[string]string{"env": "prod"}
	hash := CanonicalLabelSetHash(labels)
	filterID := uuid.New()

	input := CellInput{
		Controls:       []ControlInput{{ControlKey: controlKey}},
		LabelSets:      []LabelSetInput{{Hash: hash, Labels: labels}},
		SameSSPFilters: []VisibleFilterInput{{ID: filterID, Name: "prod", LabelSetHash: &hash}},
		Constraints: Constraints{
			OnlyAction: MappingActionExtendFilter,
		}.Normalize(),
	}

	result := ValidateRawMappings(input, []RawMapping{
		// A genuine extend against an existing same-SSP filter survives.
		{ControlKey: controlKey, LabelSetHash: hash, Action: MappingActionExtendFilter, TargetFilterID: filterID.String(), Confidence: 0.9, Reasoning: "extend", ProposedFilterLabels: map[string]string{"env": "prod"}},
		// A new_filter mapping is filtered out.
		{ControlKey: controlKey, LabelSetHash: hash, Action: MappingActionNewFilter, Confidence: 0.8, Reasoning: "new", ProposedFilterLabels: map[string]string{"env": "prod"}},
	})

	require.Equal(t, 1, result.Counts["rejected_action_filtered"])
	require.Len(t, result.Mappings, 1)
	require.Equal(t, MappingActionExtendFilter, result.Mappings[0].Action)
}

func TestConstraintsJSONMapRoundTrip(t *testing.T) {
	original := Constraints{
		MandatoryLabels: []LabelSelector{{Key: "env", Value: strptr("prod")}, {Key: "team"}},
		ExcludedLabels:  []LabelSelector{{Key: "repository"}},
		OnlyAction:      MappingActionNewFilter,
	}
	roundTripped := ConstraintsFromJSONMap(ConstraintsToJSONMap(original))
	require.Equal(t, original.Normalize(), roundTripped)

	require.Nil(t, ConstraintsToJSONMap(Constraints{}))
	require.True(t, ConstraintsFromJSONMap(nil).IsZero())
}
