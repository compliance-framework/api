package service

import (
	"context"
	//"errors"
    "fmt"

	//. "github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PlansService struct {
	planCollection     *mongo.Collection
	publisher          event.Publisher
}

func NewPlansService(p event.Publisher) *PlansService {
    return &PlansService{
        planCollection:    mongoStore.Collection("plan"),
        publisher:         p,
    }
}

func (s *PlansService) GetPlans() ([]primitive.ObjectID, error) {
    // Define a projection to only include the _id field
    projection := bson.D{
        {Key: "_id", Value: 1},
    }
    fmt.Println("Using projection:", projection)
    // Find all documents with the defined projection
    cursor, err := s.planCollection.Find(context.Background(), bson.D{}, options.Find().SetProjection(projection))
    if err != nil {
        return nil, err
    }
    var results []struct {
        ID primitive.ObjectID `bson:"_id"`
    }
    if err = cursor.All(context.Background(), &results); err != nil {
        return nil, err
    }
    fmt.Println("Results from cursor:", results)
    // Extract the _id values into a slice of ObjectID
    var ids []primitive.ObjectID
    for _, result := range results {
        ids = append(ids, result.ID)
    }
    fmt.Println("Extracted IDs:", ids)
    return ids, nil
}
