package mongo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/compliance-framework/configuration-service/internal/models/schema"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDriver struct {
	Url      string
	Database string
	client   *mongo.Client
}

func (f *MongoDriver) connect() error {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(f.Url))
	f.client = client
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
	if result.Err() != nil {
		if errors.Is(result.Err(), mongo.ErrNoDocuments) {
			return storeschema.NotFoundErr{}
		}
		return fmt.Errorf("Error when trying to find: %w", result.Err())
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
