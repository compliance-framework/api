package labelfilter

import "go.mongodb.org/mongo-driver/bson"

// MongoFilter represents a filter which is convertable to a Mongo Filter
type MongoFilter struct {
	*Scope
}

func MongoFromFilter(filter Filter) MongoFilter {
	return MongoFilter{
		Scope: filter.Scope,
	}
}

func (f *MongoFilter) GetQuery() bson.M {
	if f.Scope == nil {
		return bson.M{}
	}
	return buildQuery(f.Scope)
}

func buildQuery(scope *Scope) bson.M {
	if scope.Condition != nil {
		return buildCondition(scope.Condition)
	}

	if scope.Query != nil {
		var subQueries []bson.M
		for _, subScope := range scope.Query.Scopes {
			subQueries = append(subQueries, buildQuery(&subScope))
		}

		switch scope.Query.Operator {
		case "AND":
			return bson.M{"$and": subQueries}
		case "and":
			return bson.M{"$and": subQueries}
		case "OR":
			return bson.M{"$or": subQueries}
		case "or":
			return bson.M{"$or": subQueries}
		}
	}

	// Return an empty query if neither a Condition nor a Query is defined
	return bson.M{}
}

// buildCondition builds a MongoDB condition query
func buildCondition(condition *Condition) bson.M {
	field := "labels." + condition.Label

	switch condition.Operator {
	case "=":
		return bson.M{field: condition.Value}
	case "!=":
		return bson.M{field: bson.M{"$ne": condition.Value}}
	}

	// Default to an empty query for unsupported operators
	return bson.M{}
}
