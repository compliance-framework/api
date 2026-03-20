package labelfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeLabels(t *testing.T) {
	t.Parallel()

	labels := []struct{ Name, Value string }{
		{"Environment", "Production"},
		{"environment", "staging"},
		{" App ", " MyApp "},
		{"", "ignored"},
	}

	result := NormalizeLabels(labels)

	assert.Equal(t, []string{"production", "staging"}, result["environment"])
	assert.Equal(t, []string{"myapp"}, result["app"])
	_, exists := result[""]
	assert.False(t, exists, "empty key should be skipped")
}

func TestMatchLabels_NilScope(t *testing.T) {
	t.Parallel()

	// Nil scope matches everything.
	assert.True(t, MatchLabels(nil, map[string][]string{}))
	assert.True(t, MatchLabels(nil, map[string][]string{"a": {"b"}}))
}

func TestMatchLabels_SimpleEquals(t *testing.T) {
	t.Parallel()

	scope := &Scope{
		Condition: &Condition{Label: "env", Operator: "=", Value: "prod"},
	}

	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"prod"}}))
	assert.False(t, MatchLabels(scope, map[string][]string{"env": {"staging"}}))
	assert.False(t, MatchLabels(scope, map[string][]string{}))
}

func TestMatchLabels_CaseInsensitive(t *testing.T) {
	t.Parallel()

	scope := &Scope{
		Condition: &Condition{Label: "ENV", Operator: "=", Value: "PROD"},
	}

	// Labels are pre-normalized to lowercase by NormalizeLabels.
	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"prod"}}))
}

func TestMatchLabels_NotEquals(t *testing.T) {
	t.Parallel()

	scope := &Scope{
		Condition: &Condition{Label: "env", Operator: "!=", Value: "prod"},
	}

	assert.False(t, MatchLabels(scope, map[string][]string{"env": {"prod"}}))
	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"staging"}}))
	assert.True(t, MatchLabels(scope, map[string][]string{})) // label absent = not equal
}

func TestMatchLabels_MultipleValues(t *testing.T) {
	t.Parallel()

	scope := &Scope{
		Condition: &Condition{Label: "env", Operator: "=", Value: "prod"},
	}

	// If the label has multiple values, match if any equals.
	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"staging", "prod"}}))
}

func TestMatchLabels_ANDQuery(t *testing.T) {
	t.Parallel()

	scope := &Scope{
		Query: &Query{
			Operator: "AND",
			Scopes: []Scope{
				{Condition: &Condition{Label: "env", Operator: "=", Value: "prod"}},
				{Condition: &Condition{Label: "app", Operator: "=", Value: "web"}},
			},
		},
	}

	assert.True(t, MatchLabels(scope, map[string][]string{
		"env": {"prod"},
		"app": {"web"},
	}))

	assert.False(t, MatchLabels(scope, map[string][]string{
		"env": {"prod"},
	}))
}

func TestMatchLabels_ORQuery(t *testing.T) {
	t.Parallel()

	scope := &Scope{
		Query: &Query{
			Operator: "OR",
			Scopes: []Scope{
				{Condition: &Condition{Label: "env", Operator: "=", Value: "prod"}},
				{Condition: &Condition{Label: "env", Operator: "=", Value: "staging"}},
			},
		},
	}

	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"prod"}}))
	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"staging"}}))
	assert.False(t, MatchLabels(scope, map[string][]string{"env": {"dev"}}))
}

func TestMatchLabels_NestedQuery(t *testing.T) {
	t.Parallel()

	// env=prod AND (app=web OR app=api)
	scope := &Scope{
		Query: &Query{
			Operator: "AND",
			Scopes: []Scope{
				{Condition: &Condition{Label: "env", Operator: "=", Value: "prod"}},
				{Query: &Query{
					Operator: "OR",
					Scopes: []Scope{
						{Condition: &Condition{Label: "app", Operator: "=", Value: "web"}},
						{Condition: &Condition{Label: "app", Operator: "=", Value: "api"}},
					},
				}},
			},
		},
	}

	assert.True(t, MatchLabels(scope, map[string][]string{
		"env": {"prod"},
		"app": {"web"},
	}))

	assert.True(t, MatchLabels(scope, map[string][]string{
		"env": {"prod"},
		"app": {"api"},
	}))

	assert.False(t, MatchLabels(scope, map[string][]string{
		"env": {"prod"},
		"app": {"cli"},
	}))

	assert.False(t, MatchLabels(scope, map[string][]string{
		"env": {"staging"},
		"app": {"web"},
	}))
}

func TestMatchLabels_EmptyScope(t *testing.T) {
	t.Parallel()

	// Scope with neither condition nor query.
	scope := &Scope{}
	assert.True(t, MatchLabels(scope, map[string][]string{"a": {"b"}}))
}

func TestMatchLabels_EmptyANDScopes(t *testing.T) {
	t.Parallel()

	// AND with no sub-scopes → vacuously true.
	scope := &Scope{Query: &Query{Operator: "AND", Scopes: []Scope{}}}
	assert.True(t, MatchLabels(scope, map[string][]string{}))
}

func TestMatchLabels_EmptyORScopes(t *testing.T) {
	t.Parallel()

	// OR with no sub-scopes → vacuously true (no disjuncts).
	scope := &Scope{Query: &Query{Operator: "OR", Scopes: []Scope{}}}
	assert.True(t, MatchLabels(scope, map[string][]string{}))
}

func TestMatchLabels_UnknownOperator(t *testing.T) {
	t.Parallel()

	scope := &Scope{Query: &Query{Operator: "XOR", Scopes: []Scope{}}}
	assert.False(t, MatchLabels(scope, map[string][]string{"a": {"b"}}))
}

func TestMatchLabels_DefaultOperatorIsEquals(t *testing.T) {
	t.Parallel()

	// Empty operator string defaults to equals.
	scope := &Scope{
		Condition: &Condition{Label: "env", Operator: "", Value: "prod"},
	}
	assert.True(t, MatchLabels(scope, map[string][]string{"env": {"prod"}}))
	assert.False(t, MatchLabels(scope, map[string][]string{"env": {"staging"}}))
}
