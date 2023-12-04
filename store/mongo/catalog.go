package mongo

import (
	"context"
	"log"
	"fmt"

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

	update := bson.M{}
	if catalog.Title != "" {
			update["title"] = catalog.Title
	}
	// Incomplete list of fields that can be updated
	// Add similar checks for other fields that you want to be able to update

	if len(update) == 0 {
			return nil // No updates to apply
	}

	filter := bson.M{"_id": objID}
	_, err = store.collection.UpdateOne(context.Background(), filter, bson.M{"$set": update})
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

func (store *CatalogStoreMongo) CreateControl(catalogId string, control *domain.Control) (interface{}, error) {
	log.Println("CreateControl called with catalogId:", catalogId)

	// Create a new UUID for the control
	control.Uuid = domain.NewUuid()

	catalogObjID, err := primitive.ObjectIDFromHex(catalogId)
	if err != nil {
			log.Println("Error converting catalogId to ObjectID:", err)
			return nil, err
	}

	filter := bson.M{"_id": catalogObjID}

	// Check if 'controls' field is null
	var result bson.M
	err = store.collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
			log.Println("Error finding document:", err)
			return nil, err
	}

	// If 'controls' field is null, set it to an empty array
	if result["controls"] == nil {
			update := bson.M{
					"$set": bson.M{"controls": []bson.M{}},
			}
			_, err = store.collection.UpdateOne(context.Background(), filter, update)
			if err != nil {
					log.Println("Error updating collection:", err)
					return nil, err
			}
	}

	// Add a control to the 'controls' array
	update := bson.M{
			"$push": bson.M{"controls": *control},
	}
	_, err = store.collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
			log.Println("Error updating collection:", err)
			return nil, err
	}

	log.Println("Created control with Uuid:", control.Uuid)

	return control.Uuid, nil // Return the UUID of the control
}

func (store *CatalogStoreMongo) GetControl(catalogId string, controlId string) (*domain.Control, error) {
	catalogObjID, err := primitive.ObjectIDFromHex(catalogId)
	if err != nil {
			log.Println("Error converting catalogId to ObjectID:", err)
			return nil, err
	}

	filter := bson.M{"_id": catalogObjID}

	// Check if 'controls' field is null
	var result bson.M
	err = store.collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
			log.Println("Error finding document:", err)
			return nil, err
	}

	// If 'controls' field is null, return an error
	if result["controls"] == nil {
			log.Println("Controls field is nil")
			return nil, err
	}

	// If 'controls' field is not null, iterate over the array to find the control
	controlsPrimitiveA := result["controls"].(primitive.A)
	for _, raw := range controlsPrimitiveA {
			controlMap := raw.(primitive.M)
			control := domain.Control{}
			bsonBytes, _ := bson.Marshal(controlMap)
			bson.Unmarshal(bsonBytes, &control)

			if fmt.Sprintf("%v", control.Uuid) == controlId {
				log.Println("Found control with Uuid:", controlId)
				return &control, nil
		}
	}

	log.Println("Control not found")
	return nil, nil
}