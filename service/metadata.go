package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type DocWithMetadata struct {
	Uuid     domain.Uuid     `json:"uuid" yaml:"uuid"`
	Metadata domain.Metadata `bson:"metadata"`
}

type MetadataService struct {
	database *mongo.Database
}

func NewMetadataService(database *mongo.Database) *MetadataService {
	return &MetadataService{
		database: database,
	}
}

func (s *MetadataService) AttachMetadata(uuid string, collection string, revision domain.Revision) error {
	_, err := s.database.Collection(collection).UpdateOne(context.TODO(), bson.M{"uuid": uuid}, bson.M{
		"$addToSet": bson.M{
			"metadata.revisions": revision,
		},
	})

	return err
}
