//go:build integration

package service

import (
	"github.com/compliance-framework/configuration-service/internal/tests"
	"github.com/stretchr/testify/suite"
	"testing"
)

func TestPlans(t *testing.T) {
	suite.Run(t, new(PlanIntegrationSuite))
}

type PlanIntegrationSuite struct {
	tests.IntegrationTestSuite
}

// Keeping this here for easier implementation check in next iteration

//func (suite *PlanIntegrationSuite) TestCreateResult() {
//	suite.Run("A result can be created and stored in it's own collection", func() {
//		ctx := context.Background()
//		resultService := NewResultsService(suite.MongoDatabase)
//
//		result := &domain.Result{
//			Result: oscaltypes113.Result{
//				Title: "Testing Result",
//			},
//			Labels: map[string]string{
//				"foo": "bar",
//			},
//		}
//		if result.UUID != nil {
//			// We are not expecting and ID yet.
//			suite.T().Fatal("unexpected ID found on result object")
//		}
//		err := resultService.Create(ctx, result)
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//		if result.UUID == nil {
//			// We expect to see the ID field populated by the mongo driver.
//			suite.T().Fatal(err)
//		}
//		if err = uuid.Validate(result.UUID.String()); err != nil {
//			suite.T().Fatalf("A nil result was recived from the result service create")
//		}
//
//		// Now we ensure it exists in the database
//		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, bson.M{"_id": result.UUID})
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//		if count != 1 {
//			suite.T().Fatalf("Expected to find one result in collection")
//		}
//	})
//
//	suite.Run("A result can be stored with a stream ID", func() {
//		ctx := context.Background()
//		resultService := NewResultsService(suite.MongoDatabase)
//
//		streamId := uuid.New()
//		result := &domain.Result{
//			Result: oscaltypes113.Result{
//				Title: "Testing Result",
//			},
//			StreamID: streamId,
//			Labels: map[string]string{
//				"foo": "bar",
//			},
//		}
//		err := resultService.Create(ctx, result)
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//
//		search := bson.D{
//			bson.E{Key: "streamId", Value: streamId},
//		}
//
//		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, search)
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//		if count != 1 {
//			suite.T().Fatalf("Expected to find one result in collection")
//		}
//	})
//
//	suite.Run("A result can be stored with labels", func() {
//		ctx := context.Background()
//		resultService := NewResultsService(suite.MongoDatabase)
//
//		// Clear out all the existing results
//		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//
//		result := &domain.Result{
//			Result: oscaltypes113.Result{
//				Title: "Result",
//			},
//			Labels: map[string]string{
//				"foo": "bar",
//			},
//		}
//		err = resultService.Create(ctx, result)
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//
//		// A flake document
//		err = resultService.Create(ctx, &domain.Result{
//			Result: oscaltypes113.Result{
//				Title: "Result",
//			},
//		})
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//
//		search := bson.D{
//			{Key: "labels.foo", Value: "bar"},
//		}
//
//		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, search)
//		if err != nil {
//			suite.T().Fatal(err)
//		}
//		if count != 1 {
//			suite.T().Fatalf("Expected to find one result in collection")
//		}
//	})
//}
