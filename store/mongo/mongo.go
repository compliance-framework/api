package mongo

import (
	"context"
	"fmt"
	"sync"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	client *mongo.Client
	db     *mongo.Database
)

var mu = &sync.Mutex{}

func Connect(ctx context.Context, mongoURI, dbName string) error {
	mu.Lock()
	defer mu.Unlock()

	if client != nil {
		err := client.Ping(ctx, nil)
		if err == nil {
			return nil
		}
	}

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		return err
	}

	db = client.Database(dbName)

	return nil
}

func Disconnect() error {
	mu.Lock()
	defer mu.Unlock()

	if client == nil {
		return nil
	}

	err := client.Disconnect(context.Background())
	if err != nil {
		return err
	}

	client = nil
	db = nil
	return nil
}

func Collection(name string) *mongo.Collection {
	return db.Collection(name)
}

func InsertOne(ctx context.Context, collection string, document interface{}) (string, error) {
	result, err := db.Collection(collection).InsertOne(ctx, document)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", result.InsertedID), nil

}

func InsertMany(ctx context.Context, collection string, documents []interface{}) ([]string, error) {
	result, err := db.Collection(collection).InsertMany(ctx, documents)
	if err != nil {
		return nil, err
	}

	var ids []string = make([]string, 0)
	for _, id := range result.InsertedIDs {
		ids = append(ids, fmt.Sprintf("%v", id))
	}

	return ids, nil
}

func FindById[T any](ctx context.Context, collection string, id string) (T, error) {
	var t T

	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return t, err
	}

	result, err := FindOne[T](ctx, collection, bson.M{"_id": objectId})
	if err != nil {
		return t, err
	}

	return result, nil
}

func FindOne[T any](ctx context.Context, collection string, filter interface{}) (T, error) {
	var t T
	result := db.Collection(collection).FindOne(ctx, filter)
	if result.Err() != nil {
		return t, result.Err()
	}

	var document T
	err := result.Decode(&document)
	if err != nil {
		return t, err
	}

	return document, nil
}

func FindMany[T any](ctx context.Context, collection string, filter interface{}) ([]T, error) {
	cursor, err := db.Collection(collection).Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	var results []T = make([]T, 0)
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func UpdateOne(ctx context.Context, collection string, filter interface{}, update interface{}) (string, error) {
	result, err := db.Collection(collection).UpdateOne(ctx, filter, update)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", result.UpsertedID), nil
}

func UpdateMany(ctx context.Context, collection string, filter interface{}, update interface{}) (int64, error) {
	result, err := db.Collection(collection).UpdateMany(ctx, filter, update)
	if err != nil {
		return 0, err
	}

	return result.ModifiedCount, nil
}

func DeleteOne(ctx context.Context, collection string, filter interface{}) (int64, error) {
	result, err := db.Collection(collection).DeleteOne(ctx, filter)
	if err != nil {
		return 0, err
	}

	return result.DeletedCount, nil
}

func DeleteMany(ctx context.Context, collection string, filter interface{}) (int64, error) {
	result, err := db.Collection(collection).DeleteMany(ctx, filter)
	if err != nil {
		return 0, err
	}

	return result.DeletedCount, nil
}

func Aggregate[T any](ctx context.Context, collection string, pipeline []interface{}) ([]T, error) {
	cursor, err := db.Collection(collection).Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}

	var results []T = make([]T, 0)
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}
