package mongo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/sv-tools/mongoifc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDriver struct {
	Url      string
	Database string
	client   mongoifc.Client
}

func (f *MongoDriver) connect() error {
	client, err := mongoifc.Connect(context.TODO(), options.Client().ApplyURI(f.Url))
	if f.client == nil {
		f.client = client
	}
	return err
}
func (f *MongoDriver) disconnect() error {
	err := f.client.Disconnect(context.TODO())
	if err != nil {
		return err
	}
	f.client = nil
	return nil
}

// TODO Add tests for Update
func (f *MongoDriver) Update(id string, object schema.BaseModel) error {
	err := f.connect()
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect()
	}()
	collection := strings.Split(id, "/")[1]
	uuid := strings.Split(id, "/")[2]
	filter := bson.D{primitive.E{Key: "uuid", Value: uuid}}
	result, err := f.client.Database(f.Database).Collection(collection).ReplaceOne(context.TODO(), filter, object)
	if err != nil {
		return fmt.Errorf("could not update object: %w", err)
	}
	if result.MatchedCount == 0 {
		return storeschema.NotFoundErr{}
	}
	if result.ModifiedCount == 0 {
		return fmt.Errorf("could not modify document %v", id)
	}
	return err
}

// TODO Add tests for Create
func (f *MongoDriver) Create(id string, object schema.BaseModel) error {
	err := f.connect()
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect()
	}()
	collection := strings.Split(id, "/")[1]
	_, err = f.client.Database(f.Database).Collection(collection).InsertOne(context.TODO(), object)
	if err != nil {
		return fmt.Errorf("could not create object: %w", err)
	}
	return err
}

// TODO Add tests for Delete
func (f *MongoDriver) Delete(id string) error {
	err := f.connect()
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect()
	}()
	collection := strings.Split(id, "/")[1]
	uuid := strings.Split(id, "/")[2]
	filter := bson.D{primitive.E{Key: "uuid", Value: uuid}}
	result, err := f.client.Database(f.Database).Collection(collection).DeleteOne(context.TODO(), filter)
	if err != nil {
		return fmt.Errorf("could not update object: %w", err)
	}
	if result.DeletedCount == 0 {
		return storeschema.NotFoundErr{}
	}
	return err
}

func (f *MongoDriver) Get(id string, object schema.BaseModel) error {
	err := f.connect()
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect()
	}()
	collection := strings.Split(id, "/")[1]
	uuid := strings.Split(id, "/")[2]
	filter := bson.D{primitive.E{Key: "uuid", Value: uuid}}
	result := f.client.Database(f.Database).Collection(collection).FindOne(context.TODO(), filter)
	err = result.Err()
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return storeschema.NotFoundErr{}
		}
		return fmt.Errorf("Error when trying to find: %w", err)
	}
	err = result.Decode(object)
	if err != nil {
		return fmt.Errorf("Error decoding object: %w", err)
	}
	return err
}

func init() {
	storeschema.MustRegister("mongo", &MongoDriver{})
}
