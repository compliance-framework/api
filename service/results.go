package service

import (
	"context"
	"errors"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ResultsService struct {
	resultsCollection *mongo.Collection
}

func NewResultsService(db *mongo.Database) *ResultsService {
	return &ResultsService{
		resultsCollection: db.Collection("results"),
	}
}

func (s *ResultsService) Create(ctx context.Context, result *domain.Result) error {
	output, err := s.resultsCollection.InsertOne(ctx, result)
	if err != nil {
		return err
	}
	insertedId, ok := output.InsertedID.(primitive.ObjectID)
	if !ok {
		return errors.New("result ID is not a primitive.ObjectID")
	}
	result.Id = &insertedId
	return nil
}

func (s *ResultsService) Get(ctx context.Context, id *primitive.ObjectID) (*domain.Result, error) {
	var result domain.Result
	err := s.resultsCollection.FindOne(ctx, bson.D{
		{Key: "_id", Value: id},
	}).Decode(&result)
	return &result, err
}

func (s *ResultsService) GetAll(ctx context.Context) ([]*domain.Result, error) {
	cursor, err := s.resultsCollection.Find(ctx, bson.D{})

	if err != nil {
		return nil, err
	}
	if cursor.Err() != nil {
		return nil, cursor.Err()
	}
	defer cursor.Close(ctx)

	var results []*domain.Result
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func (s *ResultsService) GetAllForStream(ctx context.Context, streamId uuid.UUID) (results []*domain.Result, err error) {
	cursor, err := s.resultsCollection.Find(ctx, bson.D{
		bson.E{Key: "streamId", Value: streamId},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	if cursor.Err() != nil {
		return nil, cursor.Err()
	}

	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *ResultsService) GetLatestResultForStream(ctx context.Context, streamId uuid.UUID) (*domain.Result, error) {
	// Fetch the latest result
	var result domain.Result
	err := s.resultsCollection.FindOne(ctx, bson.D{
		{Key: "streamId", Value: streamId},
	}, options.FindOne().SetSort(bson.D{
		{Key: "end", Value: -1}, // -1 for descending order to get the latest result
	})).Decode(&result)
	return &result, err
}

func (s *ResultsService) GetLatestResultsForPlan(ctx context.Context, planId *primitive.ObjectID) ([]*domain.Result, error) {
	// Aggregation pipeline
	pipeline := mongo.Pipeline{
		// Match documents related to the specific plan
		{{Key: "$match", Value: bson.D{
			{Key: "relatedPlans", Value: planId},
		}}},
		// Sort by StreamID and End descending to get the latest result first
		{{Key: "$sort", Value: bson.D{
			{Key: "streamId", Value: 1}, // Group by StreamID
			{Key: "end", Value: -1},     // Latest result first
		}}},
		// Group by StreamID, taking the first document (latest due to sorting)
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$streamId"}, // Group by streamId
			{Key: "latestResult", Value: bson.D{
				{Key: "$first", Value: "$$ROOT"}, // The latest result
			}},
		}}},
	}

	// Execute aggregation
	cursor, err := s.resultsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	results := make([]*struct {
		Id     uuid.UUID     `bson:"_id"`
		Record domain.Result `bson:"latestResult"`
	}, 0)
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	output := make([]*domain.Result, 0)
	for _, result := range results {
		output = append(output, &result.Record)
	}

	return output, nil
}
