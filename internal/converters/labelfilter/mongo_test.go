package labelfilter

import (
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"testing"
)

func TestMongoFilter_Filter(t *testing.T) {
	t.Run("Simple Condition", func(t *testing.T) {
		mongoFilter := MongoFromFilter(Filter{
			&Scope{
				Condition: &Condition{
					Label:    "foo",
					Operator: "=",
					Value:    "bar",
				},
			},
		})
		assert.Equal(t, bson.M{"labels.foo": "bar"}, mongoFilter.GetQuery())
	})

	t.Run("Simple Negated Condition", func(t *testing.T) {
		mongoFilter := MongoFromFilter(Filter{
			&Scope{
				Condition: &Condition{
					Label:    "foo",
					Operator: "!=",
					Value:    "bar",
				},
			},
		})
		assert.Equal(t, bson.M{"labels.foo": bson.M{"$ne": "bar"}}, mongoFilter.GetQuery())
	})

	t.Run("Simple AND Query", func(t *testing.T) {
		mongoFilter := MongoFromFilter(Filter{
			&Scope{
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
			},
		})
		assert.Equal(t, bson.M{
			"$and": []bson.M{
				{"labels.foo": "bar"},
				{"labels.baz": "bay"},
			},
		}, mongoFilter.GetQuery())
	})

	t.Run("lowercase operators", func(t *testing.T) {
		mongoFilter := MongoFromFilter(Filter{
			&Scope{
				Query: &Query{
					Operator: "and",
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
								Operator: "or",
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
											Operator: "!=",
											Value:    "bay",
										},
									},
								},
							},
						},
					},
				},
			},
		})
		assert.Equal(t, bson.M{
			"$and": []bson.M{
				{"labels.foo": "bar"},
				{
					"$or": []bson.M{
						{"labels.foo": "bar"},
						{"labels.baz": bson.M{"$ne": "bay"}},
					},
				},
			},
		}, mongoFilter.GetQuery())
	})

	t.Run("Simple OR Query", func(t *testing.T) {
		mongoFilter := MongoFromFilter(Filter{
			&Scope{
				Query: &Query{
					Operator: "OR",
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
			},
		})
		assert.Equal(t, bson.M{
			"$or": []bson.M{
				{"labels.foo": "bar"},
				{"labels.baz": "bay"},
			},
		}, mongoFilter.GetQuery())
	})

	t.Run("Nested Query and Condition", func(t *testing.T) {
		mongoFilter := MongoFromFilter(Filter{
			&Scope{
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
											Label:    "bat",
											Operator: "=",
											Value:    "bay",
										},
									},
									{
										Condition: &Condition{
											Label:    "baz",
											Operator: "!=",
											Value:    "bay",
										},
									},
								},
							},
						},
					},
				},
			},
		})
		assert.Equal(t, bson.M{
			"$and": []bson.M{
				{"labels.foo": "bar"},
				{
					"$or": []bson.M{
						{"labels.bat": "bay"},
						{"labels.baz": bson.M{"$ne": "bay"}},
					},
				},
			},
		}, mongoFilter.GetQuery())
	})
}
