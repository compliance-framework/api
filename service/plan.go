package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlanService struct {
	planCollection *mongo.Collection
	publisher      event.Publisher
}

func NewPlanService(p event.Publisher) *PlanService {
	return &PlanService{
		planCollection: mongoStore.Collection("plan"),
		publisher:      p,
	}
}

func (s *PlanService) GetById(id string) (*domain.Plan, error) {
	plan, err := mongoStore.FindById[domain.Plan](context.Background(), "plan", id)
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (s *PlanService) Create(plan *domain.Plan) (string, error) {
	result, err := s.planCollection.InsertOne(context.TODO(), plan)
	if err != nil {
		return "", err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *PlanService) Update(plan *domain.Plan) error {
	_, err := s.planCollection.ReplaceOne(context.Background(), primitive.M{"uuid": plan.Uuid}, plan)
	if err != nil {
		return err
	}

	if plan.Scheduled() {
		err = s.publisher(event.PlanUpdated{Uuid: plan.Uuid}, event.TopicTypePlan)
		if err != nil {
			return err
		}
	}

	return nil
}
