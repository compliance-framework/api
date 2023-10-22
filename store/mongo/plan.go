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

func (c *PlanStoreMongo) CreatePlan(catalog *domain.Plan) (interface{}, error) {
	result, err := c.collection.InsertOne(context.TODO(), catalog)
	if err != nil {
		return nil, err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func NewPlanStore() *PlanStoreMongo {
	return &PlanStoreMongo{
		collection: Collection("plan"),
	}
}
