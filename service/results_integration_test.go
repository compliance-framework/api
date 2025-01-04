//go:build integration

package service

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"slices"
	"testing"
	"time"

	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/tests"
	"github.com/stretchr/testify/suite"
)

func TestResults(t *testing.T) {
	suite.Run(t, new(ResultIntegrationSuite))
}

type ResultIntegrationSuite struct {
	tests.IntegrationTestSuite
}

func (suite *ResultIntegrationSuite) TestCreateResult() {
	suite.Run("A result can be created and stored in it's own collection", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		result := &domain.Result{
			Title: "Testing Result",
		}
		if result.Id != nil {
			// We are not expecting and ID yet.
			suite.T().Fatal("unexpected ID found on result object")
		}
		err := resultService.Create(ctx, result)
		if err != nil {
			suite.T().Fatal(err)
		}
		if result.Id == nil {
			// We expect to see the ID field populated by the mongo driver.
			suite.T().Fatal(err)
		}
		if primitive.NilObjectID.Hex() == result.Id.Hex() {
			suite.T().Fatalf("A nil result was recived from the result service create")
		}

		// Now we ensure it exists in the database
		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, bson.M{"_id": result.Id})
		if err != nil {
			suite.T().Fatal(err)
		}
		if count != 1 {
			suite.T().Fatalf("Expected to find one result in collection")
		}
	})

	suite.Run("A result can be stored with a stream ID", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		streamId := uuid.New()
		result := &domain.Result{
			Title:    "Testing Result",
			StreamID: streamId,
		}
		err := resultService.Create(ctx, result)
		if err != nil {
			suite.T().Fatal(err)
		}

		search := bson.D{
			bson.E{Key: "streamId", Value: streamId},
		}

		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, search)
		if err != nil {
			suite.T().Fatal(err)
		}
		if count != 1 {
			suite.T().Fatalf("Expected to find one result in collection")
		}
	})

	suite.Run("A result can be stored related to a plan", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		planId := primitive.NewObjectID()
		extraPanId := primitive.NewObjectID()
		result := &domain.Result{
			Title: "Result",
			RelatedPlans: []*primitive.ObjectID{
				&planId,
				&extraPanId,
			},
		}
		err := resultService.Create(ctx, result)
		if err != nil {
			suite.T().Fatal(err)
		}

		// A flake document
		err = resultService.Create(ctx, &domain.Result{
			Title: "Result",
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		search := bson.D{
			{Key: "relatedPlans", Value: planId},
		}

		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, search)
		if err != nil {
			suite.T().Fatal(err)
		}
		if count != 1 {
			suite.T().Fatalf("Expected to find one result in collection")
		}
	})
}

func (suite *ResultIntegrationSuite) TestResultsByStream() {
	suite.Run("The results for a stream can be fetched", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		streamId := uuid.New()

		for i := range 2 {
			err := resultService.Create(ctx, &domain.Result{
				Title:    fmt.Sprintf("Result #%d", i),
				StreamID: streamId,
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		for i := range 2 {
			// Unrelated results
			err := resultService.Create(ctx, &domain.Result{
				Title: fmt.Sprintf("Unrelated Result #%d", i),
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		results, err := resultService.GetAllForStream(ctx, streamId)
		if err != nil {
			suite.T().Fatal(err)
		}

		// We're expecting to see 1 result
		if len(results) != 2 {
			suite.T().Fatalf("Expected to find one result in collection")
		}
	})
}

func (suite *ResultIntegrationSuite) TestResultStreams() {
	suite.Run("The latest results for each stream under a plan can be fetched", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		var err error
		var streamId uuid.UUID
		planId := primitive.NewObjectID()
		latestResults := make([]primitive.ObjectID, 0)
		for i := range 2 {
			streamId = uuid.New()
			err = resultService.Create(ctx, &domain.Result{
				Title:    fmt.Sprintf("Older result #%d", i),
				StreamID: streamId,
				RelatedPlans: []*primitive.ObjectID{
					&planId,
				},
				// Older result
				End: time.Now().Add(-1 * time.Hour),
			})
			if err != nil {
				suite.T().Fatal(err)
			}
			newResultId := primitive.NewObjectID()
			latestResults = append(latestResults, newResultId)
			err = resultService.Create(ctx, &domain.Result{
				Id:       &newResultId,
				Title:    fmt.Sprintf("Result #%d", i),
				StreamID: streamId,
				RelatedPlans: []*primitive.ObjectID{
					&planId,
				},
				// Older result
				End: time.Now(),
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		results, err := resultService.GetLatestResultsForPlan(ctx, &planId)
		if err != nil {
			suite.T().Fatal(err)
		}

		// We're expecting to see 1 result
		if len(results) != 2 {
			suite.T().Fatalf("Expected to find 2 streams in collection")
		}
		for _, result := range results {
			// Here we want to check that the result IDs are the ons from `latestResults` to make sure the latest have come back.
			if !slices.Contains(latestResults, *result.Id) {
				suite.T().Fatalf("Expected to find latest result in collection")
			}
		}
	})
}

func (suite *ResultIntegrationSuite) TestLatestStreamResult() {
	suite.Run("The latest result for a stream can be fetched", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		var err error
		var streamId = uuid.New()
		planId := primitive.NewObjectID()
		latestResult := &domain.Result{
			Title:    fmt.Sprintf("Latest result"),
			StreamID: streamId,
			RelatedPlans: []*primitive.ObjectID{
				&planId,
			},
			End: time.Now(),
		}

		// The actual latest result
		err = resultService.Create(ctx, latestResult)
		if err != nil {
			suite.T().Fatal(err)
		}

		// Create 3 older results in the stream
		for i := range 3 {
			err = resultService.Create(ctx, &domain.Result{
				Title:    fmt.Sprintf("Older result #%d", i),
				StreamID: streamId,
				RelatedPlans: []*primitive.ObjectID{
					&planId,
				},
				// Older results
				End: time.Now().Add(-time.Duration(1) * time.Hour),
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		result, err := resultService.GetLatestResultForStream(ctx, streamId)
		if err != nil {
			suite.T().Fatal(err)
		}

		if result.Id.String() != latestResult.Id.String() {
			suite.T().Fatalf("Expected to find latest result in collection. Expected %v, got %v", latestResult.Id, result.Id)
		}
	})
}

func (suite *ResultIntegrationSuite) TestGetResult() {
	suite.Run("A result can be fetched", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		var err error
		var streamId = uuid.New()
		planId := primitive.NewObjectID()
		latestResult := &domain.Result{
			Title:    fmt.Sprintf("Latest result"),
			StreamID: streamId,
			RelatedPlans: []*primitive.ObjectID{
				&planId,
			},
			End: time.Now(),
		}

		// The actual latest result
		err = resultService.Create(ctx, latestResult)
		if err != nil {
			suite.T().Fatal(err)
		}

		result, err := resultService.Get(ctx, latestResult.Id)
		if err != nil {
			suite.T().Fatal(err)
		}
		if result == nil {
			suite.T().Fatalf("Expected to find result")
		}
	})
}
