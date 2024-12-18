package mongo

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/compliance-framework/configuration-service/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type CatalogStoreMongo struct {
	collection *mongo.Collection
}

func NewCatalogStore(database *mongo.Database) *CatalogStoreMongo {
	return &CatalogStoreMongo{
		collection: database.Collection("catalog"),
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
		return fmt.Errorf("error converting id to ObjectID: %w", err)
	}

	filter := bson.M{"_id": objID}

	update := bson.M{}

	if len(catalog.Uuid) > 0 {
		update["uuid"] = catalog.Uuid
	}
	if len(catalog.Title) > 0 {
		update["title"] = catalog.Title
	}
	if len(catalog.Params) > 0 {
		update["params"] = catalog.Params
	}
	if len(catalog.Controls) > 0 {
		update["controls"] = catalog.Controls
	}
	if len(catalog.Groups) > 0 {
		update["groups"] = catalog.Groups
	}
	// BackMatter and Metadata do not have an update option

	updateOperation := bson.M{}
	if len(update) > 0 {
		updateOperation["$set"] = update
	}

	if len(updateOperation) == 0 {
		return errors.New("no fields to update provided")
	}
	_, err = store.collection.UpdateOne(context.Background(), filter, updateOperation)
	if err != nil {
		return fmt.Errorf("error updating catalog: %w", err)
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
	controlId := domain.NewUuid()
	control.Uuid = controlId

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

	log.Println("Created control with Uuid:", controlId)

	return controlId, nil // Return the UUID of the control
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
		err = bson.Unmarshal(bsonBytes, &control)
		if err != nil {
			log.Println("Error unmarshalling control:", err)
			return nil, err
		}

		if fmt.Sprintf("%v", control.Uuid) == controlId {
			return &control, nil
		}
	}

	log.Println("Control not found")
	return nil, nil
}

func (store *CatalogStoreMongo) UpdateControl(catalogId string, controlId string, control *domain.Control) (*domain.Catalog, error) {
	catalogObjID, err := primitive.ObjectIDFromHex(catalogId)
	if err != nil {
		log.Println("Invalid catalogId")
		return nil, err
	}

	filter := bson.M{
		"_id":           catalogObjID,
		"controls.uuid": controlId,
	}

	update := bson.M{}
	if control.Uuid != "" {
		update["controls.$.uuid"] = control.Uuid
	}
	if len(control.Props) > 0 {
		update["controls.$.props"] = control.Props
	}
	if len(control.Links) > 0 {
		update["controls.$.links"] = control.Links
	}
	if len(control.Parts) > 0 {
		update["controls.$.parts"] = control.Parts
	}
	if control.Class != "" {
		update["controls.$.class"] = control.Class
	}
	if control.Title != "" {
		update["controls.$.title"] = control.Title
	}
	if len(control.Params) > 0 {
		update["controls.$.params"] = control.Params
	}
	if len(control.Controls) > 0 {
		update["controls.$.controlUuids"] = control.Controls
	}

	updateOperation := bson.M{}
	if len(update) > 0 {
		updateOperation["$set"] = update
	}

	_, err = store.collection.UpdateOne(context.Background(), filter, updateOperation)
	if err != nil {
		log.Println("Error updating control:", err)
		return nil, err
	}

	// If you need to return the updated catalog, you can find it by its ID
	var updatedCatalog domain.Catalog
	err = store.collection.FindOne(context.Background(), bson.M{"_id": catalogObjID}).Decode(&updatedCatalog)
	if err != nil {
		log.Println("Error finding updated catalog:", err)
		return nil, err
	}

	return &updatedCatalog, nil
}
