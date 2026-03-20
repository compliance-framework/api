package labelfilter

import (
	"fmt"
	"slices"
	"strings"
)

// NormalizeLabels converts a slice of name/value label pairs into a map keyed
// by lowercased label name, with each value being a slice of lowercased values.
// This supports labels where a single name can have multiple values (e.g. multiple
// "_policy" labels on the same evidence).
func NormalizeLabels(labels []struct{ Name, Value string }) map[string][]string {
	result := make(map[string][]string, len(labels))
	for _, l := range labels {
		key := strings.ToLower(strings.TrimSpace(l.Name))
		val := strings.ToLower(strings.TrimSpace(l.Value))
		if key == "" {
			continue
		}
		result[key] = append(result[key], val)
	}
	return result
}

// MatchLabels evaluates a filter Scope against a normalized label map.
// A nil scope matches everything (empty filter = match all).
// Semantics mirror the SQL evaluator in evidence.go (case-insensitive via pre-normalized map).
// Returns an error if an unknown query operator is encountered.
func MatchLabels(scope *Scope, labels map[string][]string) (bool, error) {
	if scope == nil {
		return true, nil
	}
	return matchScope(*scope, labels)
}

func matchScope(scope Scope, labels map[string][]string) (bool, error) {
	if scope.IsCondition() {
		return matchCondition(*scope.Condition, labels), nil
	}
	if scope.IsQuery() {
		return matchQuery(*scope.Query, labels)
	}
	// Empty scope (neither condition nor query) matches everything.
	return true, nil
}

func matchCondition(cond Condition, labels map[string][]string) bool {
	key := strings.ToLower(strings.TrimSpace(cond.Label))
	val := strings.ToLower(strings.TrimSpace(cond.Value))

	values, exists := labels[key]

	switch cond.Operator {
	case "!=":
		// Not-equals: true if the label doesn't exist or none of its values match.
		if !exists {
			return true
		}
		if slices.Contains(values, val) {
			return false
		}
		return true
	default:
		// Equals (default): true if any value for this label matches.
		if !exists {
			return false
		}
		return slices.Contains(values, val)
	}
}

func matchQuery(query Query, labels map[string][]string) (bool, error) {
	op := strings.ToLower(query.Operator)
	switch op {
	case "and":
		for _, scope := range query.Scopes {
			match, err := matchScope(scope, labels)
			if err != nil {
				return false, err
			}
			if !match {
				return false, nil
			}
		}
		return true, nil
	case "or":
		for _, scope := range query.Scopes {
			match, err := matchScope(scope, labels)
			if err != nil {
				return false, err
			}
			if match {
				return true, nil
			}
		}
		return len(query.Scopes) == 0, nil
	default:
		return false, fmt.Errorf("unrecognised query operator: %s", query.Operator)
	}
}
