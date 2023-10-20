package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sync"
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

func InsertOne(ctx context.Context, collection string, document interface{}) (interface{}, error) {
	result, err := db.Collection(collection).InsertOne(ctx, document)
	if err != nil {
		return nil, err
	}

	return result.InsertedID, nil
}

func InsertMany(ctx context.Context, collection string, documents []interface{}) ([]interface{}, error) {
	result, err := db.Collection(collection).InsertMany(ctx, documents)
	if err != nil {
		return nil, err
	}

	return result.InsertedIDs, nil
}

func FindOne(ctx context.Context, collection string, filter interface{}) (interface{}, error) {
	result := db.Collection(collection).FindOne(ctx, filter)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var document interface{}
	err := result.Decode(&document)
	if err != nil {
		return nil, err
	}

	return document, nil
}

func FindMany(ctx context.Context, collection string, filter interface{}) ([]interface{}, error) {
	cursor, err := db.Collection(collection).Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	var documents []interface{}
	err = cursor.All(ctx, &documents)
	if err != nil {
		return nil, err
	}

	return documents, nil
}

func UpdateOne(ctx context.Context, collection string, filter interface{}, update interface{}) (interface{}, error) {
	result, err := db.Collection(collection).UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, err
	}

	return result.UpsertedID, nil
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

func Aggregate(ctx context.Context, collection string, stages []interface{}) ([]interface{}, error) {
	cursor, err := db.Collection(collection).Aggregate(ctx, stages)
	if err != nil {
		return nil, err
	}

	var results []interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}
