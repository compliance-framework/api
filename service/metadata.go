package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson"
)

type DocWithMetadata struct {
	Uuid     domain.Uuid     `json:"uuid" yaml:"uuid"`
	Metadata domain.Metadata `bson:"metadata"`
}

type MetadataService struct {
}

func NewMetadataService() *MetadataService {
	return &MetadataService{}
}

func (s *MetadataService) AttachMetadata(uuid string, collection string, revision domain.Revision) error {
	_, err := mongo.UpdateOne(context.TODO(), collection, bson.M{"uuid": uuid}, bson.M{
		"$addToSet": bson.M{
			"metadata.revisions": revision,
		},
	})

	return err
}
