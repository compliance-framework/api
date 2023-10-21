package mongo

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
	"github.com/compliance-framework/configuration-service/store"
	"go.mongodb.org/mongo-driver/mongo"
)

type CatalogStoreMongo struct {
	collection *mongo.Collection
}

func NewCatalogStore() store.CatalogStore {
	return &CatalogStoreMongo{
		collection: Collection("controls"),
	}
}

func (r *CatalogStoreMongo) CreateControl(ctx context.Context, control *catalog.Control) (interface{}, error) {
	result, err := r.collection.InsertOne(ctx, control)
	if err != nil {
		return nil, err
	}
	return result.InsertedID, nil
}
