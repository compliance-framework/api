package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// CatalogService provides CRUD operations for Catalog.
type CatalogService struct {
	collection *mongo.Collection
}

// NewCatalogService returns a new CatalogService.
func NewCatalogService(db *mongo.Database) *CatalogService {
	return &CatalogService{
		collection: db.Collection("catalogs"),
	}
}

// Create inserts a new catalog. It assigns a new UUID if missing.
func (s *CatalogService) Create(ctx context.Context, catalog *Catalog) (*Catalog, error) {
	if catalog.UUID == nil {
		id := uuid.New()
		catalog.UUID = &id
	}
	_, err := s.collection.InsertOne(ctx, catalog)
	if err != nil {
		return nil, err
	}
	return catalog, nil
}

// Get retrieves a catalog by its ID.
func (s *CatalogService) List(ctx context.Context) ([]*Catalog, error) {
	cursor, err := s.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var catalogs []*Catalog
	if err = cursor.All(ctx, &catalogs); err != nil {
		return nil, err
	}
	return catalogs, nil
}

// Get retrieves a catalog by its ID.
func (s *CatalogService) Get(ctx context.Context, id uuid.UUID) (*Catalog, error) {
	filter := bson.M{"_id": id}
	var catalog Catalog
	err := s.collection.FindOne(ctx, filter).Decode(&catalog)
	if err != nil {
		return nil, err
	}
	return &catalog, nil
}

func (s *CatalogService) FindOrCreate(ctx context.Context, catalog *Catalog) (*Catalog, error) {
	found, err := s.Get(ctx, *catalog.UUID)
	if err == nil {
		return found, nil
	}
	// Only create if the subject was not found.
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}

	return s.Create(ctx, catalog)
}
