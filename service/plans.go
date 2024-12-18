package service

import (
	"context"
	"log"

	"github.com/compliance-framework/configuration-service/event"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlansService struct {
	planCollection *mongo.Collection
	publisher      event.Publisher
}

func NewPlansService(database *mongo.Database, p event.Publisher) *PlansService {
	return &PlansService{
		planCollection: database.Collection("plan"),
		publisher:      p,
	}
}

func (s *PlansService) GetPlans() ([]bson.M, error) {
	log.Println("GetPlans")

	var pipeline mongo.Pipeline
	var results []bson.M

	pipeline = append(pipeline,
		bson.D{{Key: "$project", Value: bson.D{
			bson.E{Key: "_id", Value: 1},
			bson.E{Key: "title", Value: 1},
		}}},
	)
	cursor, err := s.planCollection.Aggregate(context.Background(), pipeline)
	if err != nil {
		return nil, err
	}

	if err = cursor.All(context.Background(), &results); err != nil {
		return nil, err
	}

	return results, nil
}
