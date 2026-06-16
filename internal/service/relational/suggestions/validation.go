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
	ID           uuid.UUID         `json:"id"`
	Name         string            `json:"name"`
	SSPID        *uuid.UUID        `json:"ssp_id,omitempty"`
	LabelSetHash *string           `json:"label_set_hash,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

type RawMappings struct {
	Mappings []RawMapping `json:"mappings"`
}

type RawMapping struct {
	ControlKey           string            `json:"control_key"`
	LabelSetHash         string            `json:"label_set_hash"`
	Action               string            `json:"action"`
	TargetFilterID       string            `json:"target_filter_id,omitempty"`
	ProposedFilterName   string            `json:"proposed_filter_name,omitempty"`
	ProposedFilterLabels map[string]string `json:"proposed_filter_labels,omitempty"`
	Confidence           float64           `json:"confidence"`
	Reasoning            string            `json:"reasoning"`
}

type ValidatedMapping struct {
	ControlKey             string
	LabelSetHash           string
	LabelSet               map[string]string
	ProposedFilterLabelSet map[string]string
	Action                 string
	TargetFilterID         *uuid.UUID
	ProposedFilterName     string
	Confidence             float64
	Reasoning              string
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
		if truncated, ok := truncateRunes(reasoning, MaxReasoningLength, ReasoningTruncatedMarker); ok {
			reasoning = truncated
			counts["reasoning_truncated"]++
		}

		filterLabels, filterLabelCounts, ok := validateProposedFilterLabels(raw.ProposedFilterLabels, labelSet.Labels)
		mergeValidationCounts(counts, filterLabelCounts)
		if !ok {
			counts["rejected_invalid_filter_labels"]++
			continue
		}

		action := raw.Action
		var targetFilterID *uuid.UUID
		if action == MappingActionExtendFilter {
			parsed, err := uuid.Parse(strings.TrimSpace(raw.TargetFilterID))
			filter, found := sameSSPFilters[parsed]
			filterLabelHash := CanonicalLabelSetHash(filterLabels)
			if err != nil || !found || filter.LabelSetHash == nil || *filter.LabelSetHash != filterLabelHash {
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
			if truncated, ok := truncateRunes(name, 120, ""); ok {
				name = truncated
				counts["name_truncated"]++
			}
		}

		mapping := ValidatedMapping{
			ControlKey:             controlKey,
			LabelSetHash:           labelSetHash,
			LabelSet:               labelSet.Labels,
			ProposedFilterLabelSet: filterLabels,
			Action:                 action,
			TargetFilterID:         targetFilterID,
			ProposedFilterName:     name,
			Confidence:             raw.Confidence,
			Reasoning:              reasoning,
		}
		dedupeKey := mappingDedupeKey(mapping)
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

func mappingDedupeKey(mapping ValidatedMapping) string {
	return mapping.ControlKey + "\x00" + CanonicalLabelSetHash(mapping.ProposedFilterLabelSet)
}

func validateProposedFilterLabels(raw map[string]string, evidenceLabels map[string]string) (map[string]string, ValidationCounts, bool) {
	counts := ValidationCounts{}
	evidence, ok := NormalizeLabelSet(evidenceLabels)
	if !ok {
		return nil, counts, false
	}

	var normalized map[string]string
	if len(raw) > 0 {
		normalized, ok = NormalizeLabelSet(raw)
		if !ok {
			return nil, counts, false
		}
	} else {
		normalized = map[string]string{}
		counts["fallback_filter_labels"]++
	}

	filterLabels := make(map[string]string, len(normalized)+1)
	for key, value := range normalized {
		if isGatheringIdentityLabel(key) {
			counts["dropped_identity_filter_labels"]++
			continue
		}
		evidenceValue, found := evidence[key]
		if !found || evidenceValue != value {
			return nil, counts, false
		}
		filterLabels[key] = value
	}

	if policy, found := evidence["_policy"]; found {
		if existing, included := filterLabels["_policy"]; included && existing != policy {
			return nil, counts, false
		}
		if _, included := filterLabels["_policy"]; !included {
			counts["added_policy_filter_label"]++
		}
		filterLabels["_policy"] = policy
	}

	if len(filterLabels) == 0 {
		filterLabels = defaultFilterLabelSubset(evidence)
		if len(filterLabels) > 0 {
			counts["fallback_filter_labels"]++
		}
	}
	if len(filterLabels) == 0 {
		return nil, counts, false
	}
	return filterLabels, counts, true
}

func defaultFilterLabelSubset(labels map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"_policy", "provider", "type"} {
		if value, found := labels[key]; found && !isGatheringIdentityLabel(key) {
			out[key] = value
		}
	}
	if len(out) > 0 {
		return out
	}

	keys := make([]string, 0, len(labels))
	for key := range labels {
		if !isGatheringIdentityLabel(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		out[key] = labels[key]
	}
	return out
}

func isGatheringIdentityLabel(key string) bool {
	switch strings.ToLower(key) {
	case "_agent", "_plugin":
		return true
	default:
		return false
	}
}

func mergeValidationCounts(dst ValidationCounts, src ValidationCounts) {
	for key, value := range src {
		dst[key] += value
	}
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
	truncated, _ := truncateRunes(name, 120, "")
	return truncated
}

func truncateRunes(value string, limit int, marker string) (string, bool) {
	if limit <= 0 {
		return value, false
	}
	count := 0
	for index := range value {
		if count == limit {
			return value[:index] + marker, true
		}
		count++
	}
	return value, false
}

func dedupeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
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
