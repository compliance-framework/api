package catalog

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/domain/model/catalog"

	"go.mongodb.org/mongo-driver/mongo"
)

type ControlRepository interface {
	Create(ctx context.Context, control *catalog.Control) (interface{}, error)
}

func NewControlRepository(collection *mongo.Collection) ControlRepository {
	return &ControlRepositoryMongo{
		collection: collection,
	}
}

type ControlRepositoryMongo struct {
	collection *mongo.Collection
}

func (r *ControlRepositoryMongo) Create(ctx context.Context, control *catalog.Control) (interface{}, error) {
	result, err := r.collection.InsertOne(ctx, control)
	if err != nil {
		return nil, err
	}
	return result.InsertedID, nil
}
