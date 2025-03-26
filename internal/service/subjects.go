package service

import (
	"context"

	"github.com/pkg/errors"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type SubjectService struct {
	collection *mongo.Collection
}

func NewSubjectService(db *mongo.Database) *SubjectService {
	return &SubjectService{
		collection: db.Collection("subjects"),
	}
}

// Create inserts a new subject. It assigns a new UUID if the subject's ID is nil,
// and returns the newly created subject with its ID populated.
func (s *SubjectService) Create(ctx context.Context, subject *Subject) (*Subject, error) {
	if subject.ID == nil {
		id := uuid.New()
		subject.ID = &id
	}
	_, err := s.collection.InsertOne(ctx, subject)
	if err != nil {
		return nil, err
	}
	return subject, nil
}

func (s *SubjectService) FindAll(ctx context.Context) ([]Subject, error) {
	cursor, err := s.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var subjects []Subject
	for cursor.Next(ctx) {
		var subject Subject
		if err := cursor.Decode(&subject); err != nil {
			return nil, err
		}
		subjects = append(subjects, subject)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return subjects, nil
}

// FindById retrieves a subject by its UUID.
func (s *SubjectService) FindById(ctx context.Context, id *uuid.UUID) (*Subject, error) {
	filter := bson.M{"_id": id}
	var subject Subject
	err := s.collection.FindOne(ctx, filter).Decode(&subject)
	if err != nil {
		return nil, err
	}
	return &subject, nil
}

// Find retrieves subjects based on a provided filter.
// The filter parameter allows flexible querying using BSON types.
func (s *SubjectService) Find(ctx context.Context, filter interface{}) ([]*Subject, error) {
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var subjects []*Subject
	for cursor.Next(ctx) {
		var subject Subject
		if err := cursor.Decode(&subject); err != nil {
			return nil, err
		}
		subjects = append(subjects, &subject)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return subjects, nil
}

// Update replaces an existing subject document identified by its UUID with the provided subject.
// If no document matches, it returns mongo.ErrNoDocuments.
func (s *SubjectService) Update(ctx context.Context, id *uuid.UUID, subject *Subject) (*Subject, error) {
	filter := bson.M{"_id": id}
	result, err := s.collection.ReplaceOne(ctx, filter, subject)
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}
	return subject, nil
}

// Delete removes a subject by its UUID and returns the deleted subject.
func (s *SubjectService) Delete(ctx context.Context, id *uuid.UUID, _ *Subject) (*Subject, error) {
	filter := bson.M{"_id": id}
	var deleted Subject
	err := s.collection.FindOneAndDelete(ctx, filter).Decode(&deleted)
	if err != nil {
		return nil, err
	}
	return &deleted, nil
}

// FindOrCreate attempts to find a subject by its UUID.
// If found, it returns the subject. If not, it uses the provided subject parameter,
// assigns the given id (if necessary), creates the subject, and returns it.
func (s *SubjectService) FindOrCreate(ctx context.Context, id *uuid.UUID, subject *Subject) (*Subject, error) {
	found, err := s.FindById(ctx, id)
	if err == nil {
		return found, nil
	}
	// Only create if the subject was not found.
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}
	// Ensure the subject has the given id.
	subject.ID = id
	return s.Create(ctx, subject)
}
