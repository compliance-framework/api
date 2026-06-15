package suggestions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const (
	MappingActionNewFilter    = "new_filter"
	MappingActionExtendFilter = "extend_filter"
)

type CellInput struct {
	Controls          []ControlInput
	LabelSets         []LabelSetInput
	VisibleFilters    []VisibleFilterInput
	SameSSPFilters    []VisibleFilterInput
	GlobalFilterNames []string
}

type ControlInput struct {
	ControlKey         string `json:"control_key"`
	CatalogID          string `json:"catalog_id"`
	ControlID          string `json:"control_id"`
	CatalogTitle       string `json:"catalog_title"`
	Title              string `json:"title"`
	Statement          string `json:"statement"`
	ImplementationText string `json:"implementation_text"`
}

type LabelSetInput struct {
	Hash          string            `json:"hash"`
	Labels        map[string]string `json:"labels"`
	EvidenceCount int               `json:"evidence_count"`
	SampleTitles  []string          `json:"sample_titles"`
}

type VisibleFilterInput struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	SSPID        *uuid.UUID `json:"ssp_id,omitempty"`
	LabelSetHash *string    `json:"label_set_hash,omitempty"`
}

type RawMappings struct {
	Mappings []RawMapping `json:"mappings"`
}

type RawMapping struct {
	ControlKey         string  `json:"control_key"`
	LabelSetHash       string  `json:"label_set_hash"`
	Action             string  `json:"action"`
	TargetFilterID     string  `json:"target_filter_id,omitempty"`
	ProposedFilterName string  `json:"proposed_filter_name,omitempty"`
	Confidence         float64 `json:"confidence"`
	Reasoning          string  `json:"reasoning"`
}

type ValidatedMapping struct {
	ControlKey         string
	LabelSetHash       string
	LabelSet           map[string]string
	Action             string
	TargetFilterID     *uuid.UUID
	ProposedFilterName string
	Confidence         float64
	Reasoning          string
}

type ValidationCounts map[string]int

type ValidationResult struct {
	Mappings []ValidatedMapping
	Counts   ValidationCounts
}

func ValidateMappings(input CellInput, raw []byte) (ValidationResult, error) {
	var decoded RawMappings
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return ValidationResult{}, err
	}
	return ValidateRawMappings(input, decoded.Mappings), nil
}

func ValidateRawMappings(input CellInput, rawMappings []RawMapping) ValidationResult {
	counts := ValidationCounts{}
	controlSet := map[string]struct{}{}
	for _, control := range input.Controls {
		controlSet[control.ControlKey] = struct{}{}
	}
	labelSets := map[string]LabelSetInput{}
	for _, labelSet := range input.LabelSets {
		labelSets[labelSet.Hash] = labelSet
	}
	sameSSPFilters := map[uuid.UUID]VisibleFilterInput{}
	for _, filter := range input.SameSSPFilters {
		sameSSPFilters[filter.ID] = filter
	}

	kept := map[string]ValidatedMapping{}
	for _, raw := range rawMappings {
		controlKey := strings.TrimSpace(raw.ControlKey)
		labelSetHash := strings.TrimSpace(raw.LabelSetHash)
		if _, ok := controlSet[controlKey]; !ok {
			counts["rejected_unknown_control"]++
			continue
		}
		labelSet, ok := labelSets[labelSetHash]
		if !ok {
			counts["rejected_unknown_label_set"]++
			continue
		}
		if raw.Confidence < 0 || raw.Confidence > 1 {
			counts["rejected_confidence_out_of_range"]++
			continue
		}
		reasoning := strings.TrimSpace(raw.Reasoning)
		if reasoning == "" {
			counts["rejected_empty_reasoning"]++
			continue
		}
		if len(reasoning) > MaxReasoningLength {
			reasoning = reasoning[:MaxReasoningLength] + ReasoningTruncatedMarker
			counts["reasoning_truncated"]++
		}

		action := raw.Action
		var targetFilterID *uuid.UUID
		if action == MappingActionExtendFilter {
			parsed, err := uuid.Parse(strings.TrimSpace(raw.TargetFilterID))
			filter, found := sameSSPFilters[parsed]
			if err != nil || !found || filter.LabelSetHash == nil || *filter.LabelSetHash != labelSetHash {
				action = MappingActionNewFilter
				counts["downgraded_extend_to_new"]++
			} else {
				targetFilterID = &parsed
			}
		}
		if action != MappingActionExtendFilter {
			action = MappingActionNewFilter
			targetFilterID = nil
		}

		name := strings.TrimSpace(raw.ProposedFilterName)
		if action == MappingActionNewFilter {
			if name == "" {
				name = fallbackFilterName(labelSet.Labels)
				counts["fallback_name"]++
			}
			if len(name) > 120 {
				name = name[:120]
				counts["name_truncated"]++
			}
		}

		mapping := ValidatedMapping{
			ControlKey:         controlKey,
			LabelSetHash:       labelSetHash,
			LabelSet:           labelSet.Labels,
			Action:             action,
			TargetFilterID:     targetFilterID,
			ProposedFilterName: name,
			Confidence:         raw.Confidence,
			Reasoning:          reasoning,
		}
		dedupeKey := controlKey + "\x00" + labelSetHash
		if existing, found := kept[dedupeKey]; !found || mapping.Confidence > existing.Confidence {
			if found {
				counts["deduped_within_cell"]++
			}
			kept[dedupeKey] = mapping
		} else {
			counts["deduped_within_cell"]++
		}
	}

	mappings := make([]ValidatedMapping, 0, len(kept))
	for _, mapping := range kept {
		mappings = append(mappings, mapping)
	}
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].ControlKey != mappings[j].ControlKey {
			return mappings[i].ControlKey < mappings[j].ControlKey
		}
		if mappings[i].Confidence != mappings[j].Confidence {
			return mappings[i].Confidence > mappings[j].Confidence
		}
		return mappings[i].LabelSetHash < mappings[j].LabelSetHash
	})

	mappings = capMappingsPerControl(mappings, counts)
	return ValidationResult{Mappings: mappings, Counts: counts}
}

func capMappingsPerControl(mappings []ValidatedMapping, counts ValidationCounts) []ValidatedMapping {
	byControl := map[string][]ValidatedMapping{}
	for _, mapping := range mappings {
		byControl[mapping.ControlKey] = append(byControl[mapping.ControlKey], mapping)
	}
	controls := make([]string, 0, len(byControl))
	for controlKey := range byControl {
		controls = append(controls, controlKey)
	}
	sort.Strings(controls)

	out := make([]ValidatedMapping, 0, len(mappings))
	for _, controlKey := range controls {
		group := byControl[controlKey]
		sort.Slice(group, func(i, j int) bool {
			if group[i].Confidence != group[j].Confidence {
				return group[i].Confidence > group[j].Confidence
			}
			return group[i].LabelSetHash < group[j].LabelSetHash
		})
		if len(group) > MaxMappingsPerControlPerCell {
			counts["dropped_control_cap"] += len(group) - MaxMappingsPerControlPerCell
			group = group[:MaxMappingsPerControlPerCell]
		}
		out = append(out, group...)
	}
	return out
}

func fallbackFilterName(labels map[string]string) string {
	lines := canonicalLabelLines(labels)
	name := strings.Join(lines, ", ")
	if name == "" {
		return "Evidence label set"
	}
	if len(name) > 120 {
		return name[:120]
	}
	return name
}

func ParseControlKey(controlKey string) (uuid.UUID, string, error) {
	catalogIDRaw, controlID, ok := strings.Cut(controlKey, ":")
	if !ok || strings.TrimSpace(controlID) == "" {
		return uuid.Nil, "", fmt.Errorf("invalid control key %q", controlKey)
	}
	catalogID, err := uuid.Parse(catalogIDRaw)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid control key %q: %w", controlKey, err)
	}
	return catalogID, controlID, nil
}

func ControlKey(catalogID uuid.UUID, controlID string) string {
	return catalogID.String() + ":" + controlID
}
