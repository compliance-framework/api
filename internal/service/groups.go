package service

import (
	"context"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// CatalogGroupService provides CRUD operations for CatalogGroup.
type CatalogGroupService struct {
	collection *mongo.Collection
}

// NewCatalogGroupService returns a new CatalogGroupService.
func NewCatalogGroupService(db *mongo.Database) *CatalogGroupService {
	return &CatalogGroupService{
		collection: db.Collection("catalog_groups"),
	}
}

// Create inserts a new catalog group. It assigns a new UUID if missing.
func (s *CatalogGroupService) Create(ctx context.Context, group *CatalogGroup) (*CatalogGroup, error) {
	if group.UUID == nil {
		id := uuid.New()
		group.UUID = &id
	}
	_, err := s.collection.InsertOne(ctx, group)
	if err != nil {
		return nil, err
	}
	return group, nil
}

// Get retrieves a catalog group by its ID.
func (s *CatalogGroupService) Get(ctx context.Context, class string, id string) (*CatalogGroup, error) {
	filter := bson.M{"id": id, "class": class}
	var group CatalogGroup
	err := s.collection.FindOne(ctx, filter).Decode(&group)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// FindFor finds catalog groups by their parent identifier.
func (s *CatalogGroupService) FindFor(ctx context.Context, parent CatalogItemParentIdentifier) ([]CatalogGroup, error) {
	filter := bson.M{
		"parent.id":    parent.ID,
		"parent.class": parent.Class,
		"parent.type":  parent.Type,
	}
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var groups []CatalogGroup
	for cursor.Next(ctx) {
		var grp CatalogGroup
		if err := cursor.Decode(&grp); err != nil {
			return nil, err
		}
		groups = append(groups, grp)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return groups, nil
}
