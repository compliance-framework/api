package mongo

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type CatalogStoreMongo struct {
	collection *mongo.Collection
}

func NewCatalogStore() *CatalogStoreMongo {
	return &CatalogStoreMongo{
		collection: Collection("catalog"),
	}
}

func (c *CatalogStoreMongo) CreateCatalog(catalog *domain.Catalog) (interface{}, error) {
	result, err := c.collection.InsertOne(context.TODO(), catalog)
	if err != nil {
		return "", err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (store *CatalogStoreMongo) GetCatalog(id string) (*domain.Catalog, error) {
    var catalog domain.Catalog
    objID, err := primitive.ObjectIDFromHex(id)
    if err != nil {
        return nil, err
    }

    filter := bson.M{"_id": objID}
    err = store.collection.FindOne(context.Background(), filter).Decode(&catalog)
    if err != nil {
        if err == mongo.ErrNoDocuments {
            return nil, nil
        }
        return nil, err
    }

    return &catalog, nil
}

func (store *CatalogStoreMongo) UpdateCatalog(id string, catalog *domain.Catalog) error {
		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
				return err
		}

		filter := bson.M{"_id": objID}
		update := bson.M{"$set": catalog}
		_, err = store.collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
				return err
		}

		return nil
}

func (store *CatalogStoreMongo) DeleteCatalog(id string) error {
		objID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
				return err
		}

		filter := bson.M{"_id": objID}
		_, err = store.collection.DeleteOne(context.Background(), filter)
		if err != nil {
				return err
		}

		return nil
}
