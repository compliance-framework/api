package mongo

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlanStoreMongo struct {
	collection *mongo.Collection
}

func NewPlanStore() *PlanStoreMongo {
	return &PlanStoreMongo{
		collection: Collection("plan"),
	}
}

func (c *PlanStoreMongo) GetById(id string) (*domain.Plan, error) {
	plan, err := FindById[domain.Plan](context.Background(), "plan", id)
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (c *PlanStoreMongo) Create(plan *domain.Plan) (interface{}, error) {
	result, err := c.collection.InsertOne(context.TODO(), plan)
	if err != nil {
		return nil, err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (c *PlanStoreMongo) Update(plan *domain.Plan) error {
	_, err := c.collection.ReplaceOne(context.Background(), primitive.M{"uuid": plan.Uuid}, plan)
	if err != nil {
		return err
	}

	return nil
}
