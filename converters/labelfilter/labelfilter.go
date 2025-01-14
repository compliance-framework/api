package labelfilter

import (
	"encoding/json"
)

// Filter represents the overarching filter for this particular set of conditions.
// It can have a condition, which is simple, or a query, which in turn can have many subqueries.
// This object is the wrapper for an entire set of queries and conditions that make up a single filter.
type Filter struct {
	Scope *Scope `json:"scope"`
}

// Condition represents a strict evaluation on a specific label.
// The Operator is a simple representation of the type of evaluation being made.
// Equals `=` and Not Equals `!=` are supported.
// In future Bigger Than `>`, Smaller Than `<` and potentially `LIKE` type searches can be supported.
type Condition struct {
	Label    string `json:"label,omitempty"`    // Label name (e.g., "type", "group", "app").
	Operator string `json:"operator,omitempty"` // Operator (e.g., "=", "!=", etc.).
	Value    string `json:"value,omitempty"`    // Value for the condition (e.g., "ssh", "prod").
}

// Query brings N Conditions or Queries together with a logical operator
// A Query can have SubQueries for searches such as:
//
// <-condition->    <-------subquery------->
// "label:value	AND (label:foo OR label:bar)"
type Query struct {
	Operator string  `json:"operator"` // Logical operator (e.g., "AND", "OR").
	Scopes   []Scope `json:"scopes"`   // Scopes can be either `Condition` or nested `Query`.
}

// Scope represents a Sub Condition or Query which can be logically represented separately or within another Scope
type Scope struct {
	*Condition `json:"condition,omitempty"`
	*Query     `json:"query,omitempty"`
}

func (qc *Scope) IsQuery() bool {
	return qc.Query != nil
}

func (qc *Scope) IsCondition() bool {
	return qc.Condition != nil
}

func (s *Scope) MarshalJSON() ([]byte, error) {
	if s.IsCondition() {
		return json.Marshal(map[string]interface{}{
			"condition": s.Condition,
		})
	}
	if s.IsQuery() {
		return json.Marshal(map[string]interface{}{
			"query": s.Query,
		})
	}
	return json.Marshal(s)
}
