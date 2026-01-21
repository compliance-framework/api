package labelfilter

import (
	"encoding/json"
	"errors"
	"strings"

	"gorm.io/gorm"
)

var (
	ErrUnrecognisedQueryOperator = errors.New("unrecognised query operator in label filter")
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

func (c *Condition) GetClause(db *gorm.DB) *gorm.DB {
	sub := db.Session(&gorm.Session{})
	labelQuery := sub.Select("1").
		Table("evidence_labels el").
		Where("el.evidence_id = l.id").
		Where("lower(el.labels_name) = lower(?)", c.Label).
		Where("lower(el.labels_value) = lower(?)", c.Value)

	if c.Operator == "!=" {
		return sub.Not("EXISTS(?)", labelQuery)
	}

	return sub.Where("EXISTS(?)", labelQuery)
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

func (q *Query) GetClause(db *gorm.DB) (*gorm.DB, error) {
	sub := db.Session(&gorm.Session{})
	switch strings.ToLower(q.Operator) {
	case "and":
		for _, scope := range q.Scopes {
			sc, err := scope.GetClause(db.Session(&gorm.Session{}))
			if err != nil {
				return nil, err
			}
			sub = sub.Where(sc)
		}
		return db.Where(sub), nil
	case "or":
		for _, scope := range q.Scopes {
			sc, err := scope.GetClause(db.Session(&gorm.Session{}))
			if err != nil {
				return nil, err
			}
			sub = sub.Or(sc)
		}
		return db.Where(sub), nil
	}
	return nil, ErrUnrecognisedQueryOperator
}

// Scope represents a Sub Condition or Query which can be logically represented separately or within another Scope
type Scope struct {
	*Condition `json:"condition,omitempty"`
	*Query     `json:"query,omitempty"`
}

func (s *Scope) IsQuery() bool {
	return s.Query != nil
}

func (s *Scope) IsCondition() bool {
	return s.Condition != nil
}

func (s *Scope) GetClause(db *gorm.DB) (*gorm.DB, error) {
	if s.IsCondition() {
		return s.Condition.GetClause(db), nil
	}

	if s.IsQuery() {
		return s.Query.GetClause(db)
	}

	return db, nil
}

func (s *Scope) MarshalJSON() ([]byte, error) {
	if s.IsCondition() {
		return json.Marshal(map[string]any{
			"condition": s.Condition,
		})
	}
	if s.IsQuery() {
		return json.Marshal(map[string]any{
			"query": s.Query,
		})
	}
	return json.Marshal(map[string]any{})
}
