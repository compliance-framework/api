package service

import (
	"context"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type ObservationService struct {
	collection *mongo.Collection
}

// NewObservationService returns a new instance of ObservationService, connected to the "observations" collection.
func NewObservationService(db *mongo.Database) *ObservationService {
	return &ObservationService{
		collection: db.Collection("observations"),
	}
}

// Create inserts a new observation. If the observation's ID is nil, a new UUID is generated.
// It returns the created observation, now including the ID.
func (s *ObservationService) Create(ctx context.Context, observation *Observation) (*Observation, error) {
	if observation.ID == nil {
		id := uuid.New()
		observation.ID = &id
	}
	_, err := s.collection.InsertOne(ctx, observation)
	if err != nil {
		return nil, err
	}
	return observation, nil
}

// FindById retrieves an observation by its primary key (ID).
func (s *ObservationService) FindById(ctx context.Context, id *uuid.UUID) (*Observation, error) {
	filter := bson.M{"_id": id}
	var observation Observation
	err := s.collection.FindOne(ctx, filter).Decode(&observation)
	if err != nil {
		return nil, err
	}
	return &observation, nil
}

// Find retrieves observations based on the provided filter. The filter can be any BSON-compatible query.
func (s *ObservationService) Find(ctx context.Context, filter any) ([]*Observation, error) {
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var observations []*Observation
	for cursor.Next(ctx) {
		var observation Observation
		if err := cursor.Decode(&observation); err != nil {
			return nil, err
		}
		observations = append(observations, &observation)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}

// Update replaces an existing observation document, identified by its ID, with the provided observation.
// It returns the updated observation, or an error if no matching document is found.
func (s *ObservationService) Update(ctx context.Context, id *uuid.UUID, observation *Observation) (*Observation, error) {
	filter := bson.M{"_id": id}
	result, err := s.collection.ReplaceOne(ctx, filter, observation)
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}
	return observation, nil
}

// Delete removes an observation by its ID and returns the deleted observation.
func (s *ObservationService) Delete(ctx context.Context, id *uuid.UUID, _ *Observation) (*Observation, error) {
	filter := bson.M{"_id": id}
	var deleted Observation
	err := s.collection.FindOneAndDelete(ctx, filter).Decode(&deleted)
	if err != nil {
		return nil, err
	}
	return &deleted, nil
}

// FindLatest returns the observation with the specified UUID that has the latest Collected field.
func (s *ObservationService) FindLatest(ctx context.Context, uuidParam uuid.UUID) (*Observation, error) {
	filter := bson.M{"uuid": uuidParam}
	opts := options.FindOne().SetSort(bson.D{{Key: "collected", Value: -1}})
	var observation Observation
	err := s.collection.FindOne(ctx, filter, opts).Decode(&observation)
	if err != nil {
		return nil, err
	}
	return &observation, nil
}

// FindByUuid returns all observations with the specified UUID ordered by the Collected field in descending order.
func (s *ObservationService) FindByUuid(ctx context.Context, uuidParam uuid.UUID) ([]*Observation, error) {
	filter := bson.M{"uuid": uuidParam}
	opts := options.Find().SetSort(bson.D{{Key: "collected", Value: -1}}).SetLimit(200)
	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var observations []*Observation
	for cursor.Next(ctx) {
		var obs Observation
		if err := cursor.Decode(&obs); err != nil {
			return nil, err
		}
		observations = append(observations, &obs)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}
