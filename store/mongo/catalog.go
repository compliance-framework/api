package mongo

import (
	"github.com/compliance-framework/configuration-service/domain/model/catalog"
	"go.mongodb.org/mongo-driver/mongo"
)

type CatalogStoreMongo struct {
	collection *mongo.Collection
}

func (c *CatalogStoreMongo) CreateCatalog(catalog *catalog.Catalog) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func NewCatalogStore() *CatalogStoreMongo {
	return &CatalogStoreMongo{}
}
