package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sync"
)

type Store struct {
	client   *mongo.Client
	db       *mongo.Database
	mu       *sync.Mutex
	ctx      context.Context
	mongoURI string
	dbName   string
}

func NewStore(ctx context.Context, mongoURI, dbName string) *Store {
	return &Store{
		mu:       &sync.Mutex{},
		ctx:      ctx,
		mongoURI: mongoURI,
		dbName:   dbName,
	}
}

func (ms *Store) Connect() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.client != nil {
		err := ms.client.Ping(ms.ctx, nil)
		if err == nil {
			return nil
		}
	}

	var err error
	ms.client, err = mongo.Connect(ms.ctx, options.Client().ApplyURI(ms.mongoURI))
	if err != nil {
		return err
	}

	ms.db = ms.client.Database(ms.dbName)

	return nil
}

func (ms *Store) Disconnect() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if ms.client == nil {
		return nil
	}

	err := ms.client.Disconnect(context.Background())
	if err != nil {
		return err
	}

	ms.client = nil
	ms.db = nil
	return nil
}

func (ms *Store) InsertOne(ctx context.Context, collection string, document interface{}) (interface{}, error) {
	result, err := ms.db.Collection(collection).InsertOne(ctx, document)
	if err != nil {
		return nil, err
	}

	return result.InsertedID, nil
}

func (ms *Store) InsertMany(ctx context.Context, collection string, documents []interface{}) ([]interface{}, error) {
	result, err := ms.db.Collection(collection).InsertMany(ctx, documents)
	if err != nil {
		return nil, err
	}

	return result.InsertedIDs, nil
}

func (ms *Store) FindOne(ctx context.Context, collection string, filter interface{}) (interface{}, error) {
	result := ms.db.Collection(collection).FindOne(ctx, filter)
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

func (ms *Store) FindMany(ctx context.Context, collection string, filter interface{}) ([]interface{}, error) {
	cursor, err := ms.db.Collection(collection).Find(ctx, filter)
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

func (ms *Store) UpdateOne(ctx context.Context, collection string, filter interface{}, update interface{}) (interface{}, error) {
	result, err := ms.db.Collection(collection).UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, err
	}

	return result.UpsertedID, nil
}

func (ms *Store) UpdateMany(ctx context.Context, collection string, filter interface{}, update interface{}) (int64, error) {
	result, err := ms.db.Collection(collection).UpdateMany(ctx, filter, update)
	if err != nil {
		return 0, err
	}

	return result.ModifiedCount, nil
}

func (ms *Store) DeleteOne(ctx context.Context, collection string, filter interface{}) (int64, error) {
	result, err := ms.db.Collection(collection).DeleteOne(ctx, filter)
	if err != nil {
		return 0, err
	}

	return result.DeletedCount, nil
}

func (ms *Store) DeleteMany(ctx context.Context, collection string, filter interface{}) (int64, error) {
	result, err := ms.db.Collection(collection).DeleteMany(ctx, filter)
	if err != nil {
		return 0, err
	}

	return result.DeletedCount, nil
}

func (ms *Store) Aggregate(ctx context.Context, collection string, stages []interface{}) ([]interface{}, error) {
	cursor, err := ms.db.Collection(collection).Aggregate(ctx, stages)
	if err != nil {
		return nil, err
	}

	var results []interface{}
	if err = cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}
