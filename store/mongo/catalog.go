package mongo

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
	"go.mongodb.org/mongo-driver/mongo"
)

type CatalogStoreMongo struct {
	collection *mongo.Collection
}

func (c *CatalogStoreMongo) CreateCatalog(catalog *catalog.Catalog) (interface{}, error) {
	result, err := c.collection.InsertOne(context.TODO(), catalog)
	if err != nil {
		return nil, err
	}
	return result.InsertedID, nil
}

func NewCatalogStore() *CatalogStoreMongo {
	return &CatalogStoreMongo{
		collection: Collection("catalog"),
	}
}
