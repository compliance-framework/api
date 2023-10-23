package store

import "context"

type Store interface {
	Connect() error
	Disconnect() error
	InsertOne(ctx context.Context, collection string, document interface{}) (interface{}, error)
	InsertMany(ctx context.Context, collection string, documents []interface{}) ([]interface{}, error)
	FindOne(ctx context.Context, collection string, filter interface{}) (interface{}, error)
	FindMany(ctx context.Context, collection string, filter interface{}) ([]interface{}, error)
	UpdateOne(ctx context.Context, collection string, filter interface{}, update interface{}) (interface{}, error)
	UpdateMany(ctx context.Context, collection string, filter interface{}, update interface{}) (int64, error)
	DeleteOne(ctx context.Context, collection string, filter interface{}) (int64, error)
	DeleteMany(ctx context.Context, collection string, filter interface{}) (int64, error)
	Aggregate(ctx context.Context, collection string, stages []interface{}) ([]interface{}, error)
}
