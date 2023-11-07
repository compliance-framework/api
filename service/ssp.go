package service

import (
	"context"
	"errors"
	"github.com/compliance-framework/configuration-service/domain"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson" 
)

var ErrSSPNotFound = errors.New("SSP not found")

type SSPService struct {
	sspCollection *mongo.Collection
}

func NewSSPService() *SSPService {
	return &SSPService {
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

func (s *SSPService) GetByID(id string) (*domain.SystemSecurityPlan, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
			return nil, err
	}

	var ssp domain.SystemSecurityPlan
	err = s.sspCollection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&ssp)
	if err != nil {
			if err == mongo.ErrNoDocuments {
					return nil, ErrSSPNotFound
			}
			return nil, err
	}

	return &ssp, nil
}

func (s *SSPService) Update(id string, ssp *domain.SystemSecurityPlan) (*domain.SystemSecurityPlan, error) {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
			return nil, err
	}

	filter := bson.M{"_id": objID}
	update := bson.M{"$set": ssp}

	result, err := s.sspCollection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
			return nil, err
	}

	if result.ModifiedCount == 0 {
			return nil, ErrSSPNotFound
	}

	return ssp, nil
}

func (s *SSPService) Delete(id string) error {
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
			return err
	}

	filter := bson.M{"_id": objID}
	result, err := s.sspCollection.DeleteOne(context.TODO(), filter)
	if err != nil {
			return err
	}

	if result.DeletedCount == 0 {
			return ErrSSPNotFound
	}

	return nil
}