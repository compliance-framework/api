package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// Component represents your struct. Ensure this is imported or defined appropriately.
// type Component struct { ... }

type ComponentService struct {
	collection *mongo.Collection
}

func NewComponentService(db *mongo.Database) *ComponentService {
	return &ComponentService{
		collection: db.Collection("components"),
	}
}

// Create inserts a new component. It assigns a new UUID if the ID is nil.
func (s *ComponentService) Create(ctx context.Context, component *Component) (*Component, error) {
	if component.ID == nil {
		id := uuid.New()
		component.ID = &id
	}
	_, err := s.collection.InsertOne(ctx, component)
	if err != nil {
		return nil, err
	}
	return component, nil
}

// FindById finds a component by its UUID.
func (s *ComponentService) FindById(ctx context.Context, id *uuid.UUID) (*Component, error) {
	filter := bson.M{"_id": id}
	var component Component
	err := s.collection.FindOne(ctx, filter).Decode(&component)
	if err != nil {
		return nil, err
	}
	return &component, nil
}

// FindByIdentifier finds a component by its identifier string.
func (s *ComponentService) FindByIdentifier(ctx context.Context, identifier string) (*Component, error) {
	filter := bson.M{"identifier": identifier}
	var component Component
	err := s.collection.FindOne(ctx, filter).Decode(&component)
	if err != nil {
		return nil, err
	}
	return &component, nil
}

// Find retrieves components based on a provided filter.
// The filter parameter allows for flexible queries using bson.M or other BSON types.
func (s *ComponentService) Find(ctx context.Context, filter interface{}) ([]*Component, error) {
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var components []*Component
	for cursor.Next(ctx) {
		var component Component
		if err := cursor.Decode(&component); err != nil {
			return nil, err
		}
		components = append(components, &component)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return components, nil
}

// Update replaces an existing component document identified by its UUID with the new component.
// This performs a full replacement update.
func (s *ComponentService) Update(ctx context.Context, id *uuid.UUID, component *Component) (*Component, error) {
	filter := bson.M{"_id": id}
	// Replace the document with the new component data.
	result, err := s.collection.ReplaceOne(ctx, filter, component)
	if err != nil {
		return nil, err
	}
	// If no document was found, return an error.
	if result.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}
	return component, nil
}

// Delete removes a component by its UUID and returns the deleted component.
func (s *ComponentService) Delete(ctx context.Context, id *uuid.UUID, _ *Component) (*Component, error) {
	filter := bson.M{"_id": id}
	var deleted Component
	// FindOneAndDelete returns the deleted document.
	err := s.collection.FindOneAndDelete(ctx, filter).Decode(&deleted)
	if err != nil {
		return nil, err
	}
	return &deleted, nil
}

// FindOrCreate attempts to find a component by its Identifier.
// If found, it returns the existing component. If not, it sets the Identifier on the provided
// component, creates it, and then returns the new component.
func (s *ComponentService) FindOrCreate(ctx context.Context, identifier string, component *Component) (*Component, error) {
	found, err := s.FindByIdentifier(ctx, identifier)
	if err == nil {
		return found, nil
	}
	// Only proceed if the error is that no document was found.
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}

	component.Identifier = identifier
	return s.Create(ctx, component)
}
