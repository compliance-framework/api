package service

import (
	"context"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type HeartbeatService struct {
	collection *mongo.Collection
}

func NewHeartbeatService(db *mongo.Database) *HeartbeatService {
	return &HeartbeatService{
		collection: db.Collection("heartbeats"),
	}
}

type Heartbeat struct {
	Id      *uuid.UUID `bson:"_id,omitempty" json:"_id"`
	Uuid    uuid.UUID  `bson:"uuid" json:"uuid"`
	Created *time.Time `bson:"created" json:"created,omitempty"`
}

// Create inserts a new component. It assigns a new UUID if the ID is nil.
func (s *HeartbeatService) Create(ctx context.Context, heartbeat *Heartbeat) (*Heartbeat, error) {
	if heartbeat.Created == nil {
		created := time.Now()
		heartbeat.Created = &created
	}
	_, err := s.collection.InsertOne(ctx, heartbeat)
	if err != nil {
		return nil, err
	}
	return heartbeat, nil
}
