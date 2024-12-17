package service

import (
	"context"
	"log"

	"github.com/compliance-framework/configuration-service/event"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlansService struct {
	planCollection *mongo.Collection
	publisher      event.Publisher
}

func NewPlansService(p event.Publisher) *PlansService {
	return &PlansService{
		planCollection: mongoStore.Collection("plan"),
		publisher:      p,
	}
}

func (s *PlansService) GetPlans() ([]bson.M, error) {
	log.Println("GetPlans")

	var pipeline mongo.Pipeline
	var results []bson.M

	pipeline = append(pipeline,
		bson.D{{"$project", bson.D{
			{"_id", 1},
			{"title", 1},
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
