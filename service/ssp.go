package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type SSPService struct {
	sspCollection *mongo.Collection
}

func NewSSPService() *SSPService {
	return &SSPService{
		sspCollection: mongoStore.Collection("ssp"),
	}
}

func (s *SSPService) Create(ssp *domain.SystemSecurityPlan) (string, error) {
	result, err := s.sspCollection.InsertOne(context.TODO(), ssp)
	if err != nil {
		return "", err
	}

	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}
