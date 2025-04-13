package service

import (
	"context"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// CatalogControlService provides CRUD operations for CatalogControl.
type CatalogControlService struct {
	collection *mongo.Collection
}

// NewCatalogControlService returns a new CatalogControlService.
func NewCatalogControlService(db *mongo.Database) *CatalogControlService {
	return &CatalogControlService{
		collection: db.Collection("catalog_controls"),
	}
}

// Create inserts a new catalog control. It assigns a new UUID if missing.
func (s *CatalogControlService) Create(ctx context.Context, control *CatalogControl) (*CatalogControl, error) {
	if control.UUID == nil {
		id := uuid.New()
		control.UUID = &id
	}
	_, err := s.collection.InsertOne(ctx, control)
	if err != nil {
		return nil, err
	}
	return control, nil
}

// Get retrieves a catalog control by its ID.
func (s *CatalogControlService) Get(ctx context.Context, class string, id string) (*CatalogControl, error) {
	filter := bson.M{"id": id, "class": class}
	var control CatalogControl
	err := s.collection.FindOne(ctx, filter).Decode(&control)
	if err != nil {
		return nil, err
	}
	return &control, nil
}

// FindFor finds catalog controls by their parent identifier.
func (s *CatalogControlService) FindFor(ctx context.Context, parent CatalogItemParentIdentifier) ([]CatalogControl, error) {
	filter := bson.M{
		"parent.catalogid": parent.CatalogId,
		"parent.type":      parent.Type,
	}
	if parent.ID != nil {
		filter["parent.id"] = *parent.ID
	}
	if parent.Class != nil {
		filter["parent.class"] = *parent.Class
	}
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	controls := make([]CatalogControl, 0)
	if err = cursor.All(ctx, &controls); err != nil {
		return nil, err
	}
	return controls, nil
}
