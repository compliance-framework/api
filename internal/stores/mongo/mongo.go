package mongo

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/sv-tools/mongoifc"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TODO Instead of having a driver structure, it might be a better idea to just have a worker pool.
type MongoDriver struct {
	Url      string
	Database string
	client   mongoifc.Client
}

func (f *MongoDriver) connect(ctx context.Context) error {
	client, err := mongoifc.Connect(ctx, options.Client().ApplyURI(f.Url))
	if f.client == nil {
		f.client = client
	}
	return err
}
func (f *MongoDriver) disconnect(ctx context.Context) error {
	err := f.client.Disconnect(ctx)
	if err != nil {
		return err
	}
	f.client = nil
	return nil
}

// TODO Add tests for Update
func (f *MongoDriver) Update(ctx context.Context, collection, id string, object interface{}) error {
	err := f.connect(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	filter := bson.D{primitive.E{Key: "uuid", Value: id}}
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
func (f *MongoDriver) Create(ctx context.Context, collection, _ string, object interface{}) error {
	err := f.connect(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	_, err = f.client.Database(f.Database).Collection(collection).InsertOne(context.TODO(), object)
	if err != nil {
		return fmt.Errorf("could not create object: %w", err)
	}
	return err
}

// TODO Add tests
func (f *MongoDriver) CreateMany(ctx context.Context, collection string, objects map[string]interface{}) error {
	docs := make([]interface{}, 0)
	for _, v := range objects {
		docs = append(docs, v)
	}
	err := f.connect(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	_, err = f.client.Database(f.Database).Collection(collection).InsertMany(ctx, docs)
	if err != nil {
		return fmt.Errorf("could not create object: %w", err)
	}
	return err
}

// TODO Add tests for DeleteWhere
func (f *MongoDriver) DeleteWhere(ctx context.Context, collection string, _ interface{}, conditions map[string]interface{}) error {
	err := f.connect(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	// Sanitizing conditions to remove `-` from the name
	// TODO - this might be better off implemented in the model with bson tags somehow.
	conditionsMap := make(map[string]interface{})
	for k, v := range conditions {
		newK := strings.ReplaceAll(k, "-", "")
		conditionsMap[newK] = v
	}
	_, err = f.client.Database(f.Database).Collection(collection).DeleteMany(ctx, conditionsMap)
	if err != nil {
		return fmt.Errorf("could not delete object: %w", err)
	}
	return err
}

// TODO Add tests for Delete
func (f *MongoDriver) Delete(ctx context.Context, collection, id string) error {
	err := f.connect(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	filter := bson.D{primitive.E{Key: "uuid", Value: id}}
	result, err := f.client.Database(f.Database).Collection(collection).DeleteOne(context.TODO(), filter)
	if err != nil {
		return fmt.Errorf("could not delete object: %w", err)
	}
	if result.DeletedCount == 0 {
		return storeschema.NotFoundErr{}
	}
	return err
}

func (f *MongoDriver) Get(ctx context.Context, collection, id string, object interface{}) error {
	err := f.connect(ctx)
	if err != nil {
		return fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	filter := bson.D{primitive.E{Key: "uuid", Value: id}}
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

func (f *MongoDriver) GetAll(ctx context.Context, collection string, object interface{}, filters ...map[string]interface{}) ([]interface{}, error) {
	objs := make([]interface{}, 0)
	err := f.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not connect to server: %w", err)
	}
	defer func() {
		err = f.disconnect(ctx)
	}()
	g := bson.D{}
	for _, filter := range filters {
		for k, v := range filter {
			// Sanitizing conditions to remove `-` from the name
			// TODO - this might be better off implemented in the model with bson tags somehow.
			newK := strings.ReplaceAll(k, "-", "")
			e := bson.E{Key: newK, Value: v}
			g = append(g, e)
		}
	}
	cursor, err := f.client.Database(f.Database).Collection(collection).Find(ctx, g)
	if err != nil {
		return nil, fmt.Errorf("could not get server: %w", err)
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		obj := reflect.New(reflect.ValueOf(object).Elem().Type()).Interface()
		err = cursor.Decode(obj)
		if err != nil {
			return nil, err
		}
		objs = append(objs, obj)
	}
	return objs, nil
}
func init() {
	storeschema.MustRegister("mongo", &MongoDriver{})
}
