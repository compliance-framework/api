package suggestions

import (
	"encoding/json"
	"sort"
	"strings"

	"gorm.io/datatypes"
)

// LabelSelector matches an evidence/filter label. A nil Value matches any value
// for the given key (key-only selector); a non-nil Value requires an exact
// (case-insensitive key) match.
type LabelSelector struct {
	Key   string  `json:"key"`
	Value *string `json:"value,omitempty"`
}

// Constraints are user-chosen, per-run output constraints applied to generated
// suggestions. They are an output constraint, not an input filter: every
// evidence label-set is still fed to the model, but suggestions that violate the
// constraints are rejected (and the constraints are surfaced in the prompt so
// the model self-limits and wastes fewer mappings).
type Constraints struct {
	// MandatoryLabels must each be satisfied by a mapping's evidence label-set,
	// and are injected into the proposed filter label set.
	MandatoryLabels []LabelSelector `json:"mandatoryLabels,omitempty"`
	// ExcludedLabels are stripped from a mapping's proposed filter label set.
	ExcludedLabels []LabelSelector `json:"excludedLabels,omitempty"`
	// OnlyAction, when set, keeps only mappings whose final action matches it.
	// Empty means no action restriction. Valid values: MappingActionNewFilter,
	// MappingActionExtendFilter.
	OnlyAction string `json:"onlyAction,omitempty"`
}

// IsZero reports whether no constraints are configured.
func (c Constraints) IsZero() bool {
	return len(c.MandatoryLabels) == 0 && len(c.ExcludedLabels) == 0 && strings.TrimSpace(c.OnlyAction) == ""
}

// Normalize trims keys, lowercases them to match NormalizeLabelSet semantics,
// drops empty-key selectors, and sorts for stable prompt rendering.
func (c Constraints) Normalize() Constraints {
	c.MandatoryLabels = normalizeSelectors(c.MandatoryLabels)
	c.ExcludedLabels = normalizeSelectors(c.ExcludedLabels)
	c.OnlyAction = strings.TrimSpace(c.OnlyAction)
	return c
}

func normalizeSelectors(selectors []LabelSelector) []LabelSelector {
	out := make([]LabelSelector, 0, len(selectors))
	for _, selector := range selectors {
		key := strings.ToLower(strings.TrimSpace(selector.Key))
		if key == "" {
			continue
		}
		normalized := LabelSelector{Key: key}
		if selector.Value != nil {
			value := strings.TrimSpace(*selector.Value)
			normalized.Value = &value
		}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return selectorValue(out[i]) < selectorValue(out[j])
	})
	return out
}

func selectorValue(selector LabelSelector) string {
	if selector.Value == nil {
		return ""
	}
	return *selector.Value
}

// evidenceSatisfies reports whether a (normalized) evidence label set satisfies
// the selector: the key must be present, and the value must match when the
// selector specifies one.
func (selector LabelSelector) evidenceSatisfies(evidence map[string]string) (string, bool) {
	value, found := evidence[selector.Key]
	if !found {
		return "", false
	}
	if selector.Value != nil && *selector.Value != value {
		return "", false
	}
	return value, true
}

// matchesLabel reports whether the selector matches a single key=value pair.
func (selector LabelSelector) matchesLabel(key, value string) bool {
	if strings.ToLower(key) != selector.Key {
		return false
	}
	return selector.Value == nil || *selector.Value == value
}

// applyLabelConstraints enforces mandatory/excluded label constraints against a
// single mapping's proposed filter labels. evidence is the normalized evidence
// label set; filterLabels is mutated in place (mandatory labels injected,
// excluded labels stripped). It returns ok=false when the evidence cannot
// satisfy a mandatory selector, or when exclusions empty the filter labels.
func applyLabelConstraints(c Constraints, evidence, filterLabels map[string]string, counts ValidationCounts) (map[string]string, bool) {
	mandatory := make(map[string]string, len(c.MandatoryLabels))
	for _, selector := range c.MandatoryLabels {
		value, ok := selector.evidenceSatisfies(evidence)
		if !ok {
			counts["rejected_missing_mandatory_label"]++
			return nil, false
		}
		mandatory[selector.Key] = value
	}

	for key, value := range filterLabels {
		for _, selector := range c.ExcludedLabels {
			if selector.matchesLabel(key, value) {
				delete(filterLabels, key)
				counts["dropped_excluded_filter_labels"]++
				break
			}
		}
	}

	// Re-add mandatory labels after exclusions so a contradictory selection
	// (same key marked mandatory and excluded) keeps the mandatory label.
	for key, value := range mandatory {
		filterLabels[key] = value
	}

	if len(filterLabels) == 0 {
		counts["rejected_excluded_emptied"]++
		return nil, false
	}
	return filterLabels, true
}

// describeConstraints renders constraints as human-readable prompt guidance so
// the model self-limits. Returns "" when there are no constraints.
func describeConstraints(c Constraints) string {
	c = c.Normalize()
	if c.IsZero() {
		return ""
	}
	lines := make([]string, 0, 3)
	if len(c.MandatoryLabels) > 0 {
		lines = append(lines, "- Only map evidence whose labels include all of these, and include them in proposed_filter_labels: "+selectorList(c.MandatoryLabels)+".")
	}
	if len(c.ExcludedLabels) > 0 {
		lines = append(lines, "- Never include these labels in proposed_filter_labels: "+selectorList(c.ExcludedLabels)+".")
	}
	switch c.OnlyAction {
	case MappingActionNewFilter:
		lines = append(lines, "- Only propose new_filter mappings; do not extend existing dashboards.")
	case MappingActionExtendFilter:
		lines = append(lines, "- Only propose extend_filter mappings against this plan's existing dashboards; do not create new ones.")
	}
	return strings.Join(lines, "\n")
}

func selectorList(selectors []LabelSelector) string {
	parts := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		if selector.Value != nil {
			parts = append(parts, selector.Key+"="+*selector.Value)
		} else {
			parts = append(parts, selector.Key+" (any value)")
		}
	}
	return strings.Join(parts, ", ")
}

// ConstraintsToJSONMap serializes constraints for storage on a run. Returns nil
// for empty constraints so the column stays null.
func ConstraintsToJSONMap(c Constraints) datatypes.JSONMap {
	c = c.Normalize()
	if c.IsZero() {
		return nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var out datatypes.JSONMap
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// ConstraintsFromJSONMap deserializes constraints stored on a run.
func ConstraintsFromJSONMap(m datatypes.JSONMap) Constraints {
	if len(m) == 0 {
		return Constraints{}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return Constraints{}
	}
	var c Constraints
	if err := json.Unmarshal(raw, &c); err != nil {
		return Constraints{}
	}
	return c.Normalize()
}
