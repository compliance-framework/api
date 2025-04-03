package service

import (
	"context"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type DashboardService struct {
	collection *mongo.Collection
}

func NewDashboardService(database *mongo.Database) *DashboardService {
	return &DashboardService{
		collection: database.Collection("dashboards"),
	}
}

func (s *DashboardService) Get(ctx context.Context, id uuid.UUID) (*Dashboard, error) {
	output := s.collection.FindOne(ctx, bson.D{bson.E{Key: "_id", Value: id}})
	if output.Err() != nil {
		return nil, output.Err()
	}

	result := &Dashboard{}
	err := output.Decode(result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func (s *DashboardService) List(ctx context.Context) (*[]Dashboard, error) {
	cursor, err := s.collection.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}

	results := &[]Dashboard{}
	if err = cursor.All(ctx, results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *DashboardService) Create(ctx context.Context, dashboard *Dashboard) (*Dashboard, error) {
	if dashboard.UUID == nil {
		newId := uuid.New()
		dashboard.UUID = &newId
	}
	_, err := s.collection.InsertOne(ctx, dashboard)
	if err != nil {
		return dashboard, err
	}
	return dashboard, nil
}
