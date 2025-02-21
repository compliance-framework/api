package labelfilter

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestScopeMarshalling ensures a scope can be serialised and deserialized from JSON to support storing it in a data store
func TestScopeMarshalling(t *testing.T) {
	t.Run("Single Condition", func(t *testing.T) {
		scope := Scope{
			Condition: &Condition{
				Label:    "foo",
				Operator: "=",
				Value:    "bar",
			},
		}

		marshalled, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}

		expectedMarshalled, err := json.Marshal(map[string]map[string]string{
			"condition": {
				"label":    "foo",
				"operator": "=",
				"value":    "bar",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		assert.JSONEq(t, string(expectedMarshalled), string(marshalled))
	})

	t.Run("Simple Query", func(t *testing.T) {
		scope := Scope{
			Query: &Query{
				Operator: "AND",
				Scopes: []Scope{
					{
						Condition: &Condition{
							Label:    "foo",
							Operator: "=",
							Value:    "bar",
						},
					},
					{
						Condition: &Condition{
							Label:    "baz",
							Operator: "=",
							Value:    "bay",
						},
					},
				},
			},
		}

		marshalled, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}

		expectedMarshalled, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]map[string]string{
					{"condition": {"label": "foo", "operator": "=", "value": "bar"}},
					{"condition": {"label": "baz", "operator": "=", "value": "bay"}},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		assert.JSONEq(t, string(expectedMarshalled), string(marshalled))
	})

	t.Run("Single Nested Query", func(t *testing.T) {
		scope := Scope{
			Query: &Query{
				Operator: "AND",
				Scopes: []Scope{
					{
						Condition: &Condition{
							Label:    "foo",
							Operator: "=",
							Value:    "bar",
						},
					},
					{
						Query: &Query{
							Operator: "OR",
							Scopes: []Scope{
								{
									Condition: &Condition{
										Label:    "top",
										Operator: "=",
										Value:    "foo",
									},
								},
								{
									Condition: &Condition{
										Label:    "type",
										Operator: "=",
										Value:    "bar",
									},
								},
							},
						},
					},
				},
			},
		}

		marshalled, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}

		expectedMarshalled, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]interface{}{
					{
						"condition": map[string]interface{}{
							"label":    "foo",
							"operator": "=",
							"value":    "bar",
						},
					},
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]map[string]string{
								{"condition": {"label": "top", "operator": "=", "value": "foo"}},
								{"condition": {"label": "type", "operator": "=", "value": "bar"}},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		assert.JSONEq(t, string(expectedMarshalled), string(marshalled))
	})

	t.Run("Nested Queries", func(t *testing.T) {
		scope := Scope{
			Query: &Query{
				Operator: "AND",
				Scopes: []Scope{
					{
						Query: &Query{
							Operator: "OR",
							Scopes: []Scope{
								{
									Condition: &Condition{
										Label:    "foo",
										Operator: "=",
										Value:    "foo",
									},
								},
								{
									Condition: &Condition{
										Label:    "bar",
										Operator: "=",
										Value:    "bar",
									},
								},
							},
						},
					},
					{
						Query: &Query{
							Operator: "OR",
							Scopes: []Scope{
								{
									Condition: &Condition{
										Label:    "baz",
										Operator: "=",
										Value:    "baz",
									},
								},
								{
									Condition: &Condition{
										Label:    "bay",
										Operator: "=",
										Value:    "bay",
									},
								},
							},
						},
					},
				},
			},
		}

		marshalled, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}

		expectedMarshalled, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]interface{}{
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]map[string]string{
								{"condition": {"label": "foo", "operator": "=", "value": "foo"}},
								{"condition": {"label": "bar", "operator": "=", "value": "bar"}},
							},
						},
					},
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]map[string]string{
								{"condition": {"label": "baz", "operator": "=", "value": "baz"}},
								{"condition": {"label": "bay", "operator": "=", "value": "bay"}},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		assert.JSONEq(t, string(expectedMarshalled), string(marshalled))
	})

	t.Run("Double Nested Queries", func(t *testing.T) {
		scope := Scope{
			Query: &Query{
				Operator: "AND",
				Scopes: []Scope{
					{
						Query: &Query{
							Operator: "OR",
							Scopes: []Scope{
								{
									Query: &Query{
										Operator: "AND",
										Scopes: []Scope{
											{
												Condition: &Condition{
													Label:    "foo",
													Operator: "=",
													Value:    "foo",
												},
											},
											{
												Condition: &Condition{
													Label:    "bar",
													Operator: "=",
													Value:    "bar",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		marshalled, err := json.Marshal(scope)
		if err != nil {
			t.Fatal(err)
		}

		expectedMarshalled, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]interface{}{
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]interface{}{
								{
									"query": map[string]interface{}{
										"operator": "AND",
										"scopes": []map[string]map[string]string{
											{"condition": {"label": "foo", "operator": "=", "value": "foo"}},
											{"condition": {"label": "bar", "operator": "=", "value": "bar"}},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		assert.JSONEq(t, string(expectedMarshalled), string(marshalled))
	})
}

func TestScopeUnmarshalling(t *testing.T) {
	t.Run("Single Condition", func(t *testing.T) {
		scope := &Scope{}
		scopeJson, err := json.Marshal(map[string]map[string]string{
			"condition": {
				"label":    "foo",
				"operator": "=",
				"value":    "bar",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if json.Unmarshal(scopeJson, scope) != nil {
			t.Fatal(err)
		}

		assert.True(t, scope.IsCondition())
		assert.False(t, scope.IsQuery())
		assert.True(t, scope.Condition.Label == "foo")
		assert.True(t, scope.Condition.Operator == "=")
		assert.True(t, scope.Condition.Value == "bar")
	})

	t.Run("Simple Query", func(t *testing.T) {
		scope := &Scope{}
		scopeJson, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]map[string]string{
					{"condition": {"label": "foo", "operator": "=", "value": "bar"}},
					{"condition": {"label": "baz", "operator": "!=", "value": "bay"}},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if json.Unmarshal(scopeJson, scope) != nil {
			t.Fatal(err)
		}

		assert.False(t, scope.IsCondition())
		assert.True(t, scope.IsQuery())

		assert.True(t, len(scope.Query.Scopes) == 2)
		assert.True(t, scope.Query.Scopes[0].IsCondition())
		assert.True(t, scope.Query.Scopes[1].IsCondition())
		assert.False(t, scope.Query.Scopes[0].IsQuery())
		assert.False(t, scope.Query.Scopes[1].IsQuery())

		// We'll check the baz condition
		spotCondition := scope.Query.Scopes[0].Condition
		if spotCondition.Label == "foo" {
			spotCondition = scope.Query.Scopes[1].Condition
		}

		assert.True(t, spotCondition.Label == "baz")
		assert.True(t, spotCondition.Operator == "!=")
		assert.True(t, spotCondition.Value == "bay")

		// Spot checks
	})

	t.Run("Single Nested Query", func(t *testing.T) {
		scope := &Scope{}
		scopeJson, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]interface{}{
					{
						"condition": map[string]interface{}{
							"label":    "foo",
							"operator": "=",
							"value":    "bar",
						},
					},
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]map[string]string{
								{"condition": {"label": "top", "operator": "=", "value": "foo"}},
								{"condition": {"label": "type", "operator": "=", "value": "bar"}},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if json.Unmarshal(scopeJson, scope) != nil {
			t.Fatal(err)
		}

		assert.False(t, scope.IsCondition())
		assert.True(t, scope.IsQuery())
		assert.True(t, len(scope.Query.Scopes) == 2)

		condition := scope.Query.Scopes[0]
		query := scope.Query.Scopes[1]

		if scope.Query.Scopes[1].IsCondition() {
			// Flip it
			condition = scope.Query.Scopes[1]
			query = scope.Query.Scopes[0]
		}

		assert.True(t, condition.IsCondition())
		assert.True(t, query.IsQuery())
	})

	t.Run("Nested Queries", func(t *testing.T) {
		scope := &Scope{}
		scopeJson, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]interface{}{
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]map[string]string{
								{"condition": {"label": "foo", "operator": "=", "value": "foo"}},
								{"condition": {"label": "bar", "operator": "=", "value": "bar"}},
							},
						},
					},
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]map[string]string{
								{"condition": {"label": "baz", "operator": "=", "value": "baz"}},
								{"condition": {"label": "bay", "operator": "=", "value": "bay"}},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if json.Unmarshal(scopeJson, scope) != nil {
			t.Fatal(err)
		}

		assert.False(t, scope.IsCondition())
		assert.True(t, scope.IsQuery())
		assert.True(t, len(scope.Query.Scopes) == 2)
		assert.True(t, scope.Scopes[0].IsQuery())
		assert.True(t, scope.Scopes[1].IsQuery())
	})

	t.Run("Double Nested Queries", func(t *testing.T) {
		scope := &Scope{}
		scopeJson, err := json.Marshal(map[string]interface{}{
			"query": map[string]interface{}{
				"operator": "AND",
				"scopes": []map[string]interface{}{
					{
						"query": map[string]interface{}{
							"operator": "OR",
							"scopes": []map[string]interface{}{
								{
									"query": map[string]interface{}{
										"operator": "AND",
										"scopes": []map[string]map[string]string{
											{"condition": {"label": "foo", "operator": "=", "value": "foo"}},
											{"condition": {"label": "bar", "operator": "=", "value": "bar"}},
										},
									},
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if json.Unmarshal(scopeJson, scope) != nil {
			t.Fatal(err)
		}

		assert.False(t, scope.IsCondition())
		assert.True(t, scope.IsQuery())
		assert.True(t, scope.Query.Scopes[0].IsQuery())
		assert.True(t, scope.Query.Scopes[0].IsQuery())
		assert.True(t, scope.Query.Scopes[0].Scopes[0].IsQuery())
		assert.True(t, scope.Query.Scopes[0].Scopes[0].Scopes[0].IsCondition())
	})
}
