package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/domain"
	"github.com/google/uuid"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlansService struct {
	planCollection *mongo.Collection
}

func NewPlansService(database *mongo.Database) *PlansService {
	return &PlansService{
		planCollection: database.Collection("plan"),
	}
}

func (s *PlansService) GetPlans() (*[]domain.Plan, error) {
	log.Println("GetPlans")

	results := &[]domain.Plan{}

	cursor, err := s.planCollection.Find(context.Background(), bson.D{})
	if err != nil {
		return nil, err
	}

	if err = cursor.All(context.Background(), results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *PlansService) GetById(ctx context.Context, id uuid.UUID) (*domain.Plan, error) {
	output := s.planCollection.FindOne(ctx, bson.D{bson.E{Key: "_id", Value: id}})
	if output.Err() != nil {
		return nil, output.Err()
	}

	result := &domain.Plan{}
	err := output.Decode(result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func (s *PlansService) Create(plan *domain.Plan) (*domain.Plan, error) {
	log.Println("Create")
	if plan.UUID == nil {
		newId := uuid.New()
		plan.UUID = &newId
	}
	_, err := s.planCollection.InsertOne(context.TODO(), plan)
	if err != nil {
		return plan, err
	}
	return plan, nil
}
