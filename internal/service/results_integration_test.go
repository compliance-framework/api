//go:build integration

package service

import (
	"context"
	"fmt"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/domain"
	"github.com/compliance-framework/configuration-service/internal/tests"
	oscaltypes113 "github.com/defenseunicorns/go-oscal/src/types/oscal-1-1-3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

func newUUID() *uuid.UUID {
	id := uuid.New()
	return &id
}

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
			Result: oscaltypes113.Result{
				Title: "Testing Result",
			},
		}
		if result.UUID != nil {
			// We are not expecting and ID yet.
			suite.T().Fatal("unexpected ID found on result object")
		}
		err := resultService.Create(ctx, result)
		if err != nil {
			suite.T().Fatal(err)
		}
		if result.UUID == nil {
			// We expect to see the ID field populated by the mongo driver.
			suite.T().Fatal(err)
		}
		if err = uuid.Validate(result.UUID.String()); err != nil {
			suite.T().Fatalf("A nil result was recived from the result service create")
		}

		// Now we ensure it exists in the database
		count, err := suite.MongoDatabase.Collection("results").CountDocuments(ctx, bson.M{"_id": result.UUID})
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
			Result: oscaltypes113.Result{
				Title: "Testing Result",
			},
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

	suite.Run("A result can be stored with labels", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		planId := primitive.NewObjectID()
		result := &domain.Result{
			Result: oscaltypes113.Result{
				Title: "Result",
			},
			Labels: map[string]string{
				"plan_id": planId.String(),
				"foo":     "bar",
			},
		}
		err := resultService.Create(ctx, result)
		if err != nil {
			suite.T().Fatal(err)
		}

		// A flake document
		err = resultService.Create(ctx, &domain.Result{
			Result: oscaltypes113.Result{
				Title: "Result",
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		search := bson.D{
			{Key: "labels.plan_id", Value: planId.String()},
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

func (suite *ResultIntegrationSuite) TestResultSearch() {
	suite.Run("Simple", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Create a few with sequential timestamps
		streamId := uuid.New()
		theTime := time.Now()
		err = resultService.Create(ctx, &domain.Result{
			Result: oscaltypes113.Result{
				Title: "Testing Result #1",
				End:   &theTime,
			},
			StreamID: streamId,
		})
		if err != nil {
			suite.T().Fatal(err)
		}
		endTime := time.Now().Add(-time.Minute)
		err = resultService.Create(ctx, &domain.Result{
			Result: oscaltypes113.Result{
				Title: "Testing Result #2",
				End:   &endTime,
			},
			StreamID: streamId,
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 1, len(results))
		assert.Equal(suite.T(), streamId, results[0].StreamID)
		assert.Equal(suite.T(), "Testing Result #1", results[0].Title)
	})

	suite.Run("Multiple Streams", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Give us a consistent order
		stream1 := uuid.MustParse("3dfae71a-a1a0-4b25-9abc-4cc6838a95bb")
		stream2 := uuid.MustParse("c087f2c4-5dc5-4b16-9ddf-74610856976a")
		theTime := time.Now()
		endTime := time.Now().Add(-time.Minute)
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: stream1,
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &endTime,
				},
				StreamID: stream1,
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #2-#1",
					End:   &theTime,
				},
				StreamID: stream2,
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #2-#2",
					End:   &endTime,
				},
				StreamID: stream2,
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 2, len(results))
		assert.Contains(suite.T(), []string{"Res #1-#1", "Res #2-#1"}, results[0].Title)
		assert.Contains(suite.T(), []string{"Res #1-#1", "Res #2-#1"}, results[1].Title)
	})

	suite.Run("Simple Search", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		theTime := time.Now()
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: uuid.New(),
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theTime,
				},
				StreamID: uuid.New(),
				Labels: map[string]string{
					"foo": "baz",
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "foo",
					Operator: "=",
					Value:    "bar",
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 1, len(results))
		assert.Equal(suite.T(), "Res #1-#1", results[0].Title)
	})

	suite.Run("Simple Negated Search", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Give us a consistent order
		stream1 := uuid.MustParse("3dfae71a-a1a0-4b25-9abc-4cc6838a95bb")
		stream2 := uuid.MustParse("c087f2c4-5dc5-4b16-9ddf-74610856976a")
		theTime := time.Now()
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: stream1,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theTime,
				},
				StreamID: stream2,
				Labels: map[string]string{
					"foo": "baz",
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Condition: &labelfilter.Condition{
					Label:    "foo",
					Operator: "!=",
					Value:    "bar",
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 1, len(results))
		assert.Equal(suite.T(), "Res #1-#2", results[0].Title)
	})

	suite.Run("Complexer query", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Give us a consistent order
		stream1 := uuid.MustParse("3dfae71a-a1a0-4b25-9abc-4cc6838a95bb")
		stream2 := uuid.MustParse("c087f2c4-5dc5-4b16-9ddf-74610856976a")
		theTime := time.Now()
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: stream1,
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theTime,
				},
				StreamID: stream2,
				Labels: map[string]string{
					"foo": "baz",
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Query: &labelfilter.Query{
					Operator: "OR",
					Scopes: []labelfilter.Scope{
						{
							Condition: &labelfilter.Condition{
								Label:    "foo",
								Operator: "=",
								Value:    "bar",
							},
						},
						{
							Condition: &labelfilter.Condition{
								Label:    "foo",
								Operator: "=",
								Value:    "baz",
							},
						},
					},
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 2, len(results))
		assert.Contains(suite.T(), []string{"Res #1-#1", "Res #1-#2"}, results[0].Title)
		assert.Contains(suite.T(), []string{"Res #1-#1", "Res #1-#2"}, results[1].Title)
	})

	suite.Run("Complex sub query", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Give us a consistent order
		stream1 := uuid.MustParse("3dfae71a-a1a0-4b25-9abc-4cc6838a95bb")
		stream2 := uuid.MustParse("c087f2c4-5dc5-4b16-9ddf-74610856976a")
		theTime := time.Now()
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: stream1,
				Labels: map[string]string{
					"foo": "bar",
					"bar": "baz",
				},
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theTime,
				},
				StreamID: stream2,
				Labels: map[string]string{
					"foo": "bar",
					"baz": "bat",
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Query: &labelfilter.Query{
					Operator: "and",
					Scopes: []labelfilter.Scope{
						{
							Condition: &labelfilter.Condition{
								Label:    "foo",
								Operator: "=",
								Value:    "bar",
							},
						},
						{
							Query: &labelfilter.Query{
								Operator: "or",
								Scopes: []labelfilter.Scope{
									{
										Condition: &labelfilter.Condition{
											Label:    "bar",
											Operator: "=",
											Value:    "baz",
										},
									},
									{
										Condition: &labelfilter.Condition{
											Label:    "baz",
											Operator: "=",
											Value:    "bat",
										},
									},
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 2, len(results))
		assert.Contains(suite.T(), []string{"Res #1-#1", "Res #1-#2"}, results[0].Title)
		assert.Contains(suite.T(), []string{"Res #1-#1", "Res #1-#2"}, results[1].Title)
	})

	suite.Run("Complex sub query with negation", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		// Give us a consistent order
		stream1 := uuid.MustParse("3dfae71a-a1a0-4b25-9abc-4cc6838a95bb")
		stream2 := uuid.MustParse("c087f2c4-5dc5-4b16-9ddf-74610856976a")
		theTime := time.Now()
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: stream1,
				Labels: map[string]string{
					"foo": "bar",
					"bar": "baz",
				},
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theTime,
				},
				StreamID: stream2,
				Labels: map[string]string{
					"foo": "bar",
					"baz": "bat",
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{
			Scope: &labelfilter.Scope{
				Query: &labelfilter.Query{
					Operator: "and",
					Scopes: []labelfilter.Scope{
						{
							Condition: &labelfilter.Condition{
								Label:    "foo",
								Operator: "=",
								Value:    "bar",
							},
						},
						{
							Query: &labelfilter.Query{
								Operator: "and",
								Scopes: []labelfilter.Scope{
									{
										Condition: &labelfilter.Condition{
											Label:    "bar",
											Operator: "!=",
											Value:    "baz",
										},
									},
									{
										Condition: &labelfilter.Condition{
											Label:    "bar",
											Operator: "!=",
											Value:    "baz",
										},
									},
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Equal(suite.T(), 1, len(results))
		assert.Equal(suite.T(), "Res #1-#2", results[0].Title)
	})
}

func (suite *ResultIntegrationSuite) TestResultsByStream() {
	suite.Run("The results for a stream can be fetched", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		streamId := uuid.New()

		for i := range 2 {
			err := resultService.Create(ctx, &domain.Result{
				Result: oscaltypes113.Result{
					Title: fmt.Sprintf("Result #%d", i),
				},
				StreamID: streamId,
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		for i := range 2 {
			// Unrelated results
			err := resultService.Create(ctx, &domain.Result{
				Result: oscaltypes113.Result{
					Title: fmt.Sprintf("Unrelated Result #%d", i),
				},
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

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		var streamId uuid.UUID
		latestResults := make([]uuid.UUID, 0)
		for i := range 2 {
			streamId = uuid.New()
			theTime := time.Now()
			endTime := time.Now().Add(-1 * time.Hour)
			err = resultService.Create(ctx, &domain.Result{
				Result: oscaltypes113.Result{
					Title: fmt.Sprintf("Older result #%d", i),
					End:   &endTime,
				},
				StreamID: streamId,
				// Older result
				Labels: map[string]string{
					"foo": "bar",
				},
			})
			if err != nil {
				suite.T().Fatal(err)
			}
			newResultId := uuid.New()
			latestResults = append(latestResults, newResultId)
			err = resultService.Create(ctx, &domain.Result{
				Result: oscaltypes113.Result{
					Title: fmt.Sprintf("Result #%d", i),
					End:   &theTime,
				},
				UUID:     &newResultId,
				StreamID: streamId,
				// Older result
				Labels: map[string]string{
					"foo": "bar",
				},
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		results, err := resultService.GetLatestResultsForPlan(ctx, &domain.Plan{
			ResultFilter: labelfilter.Filter{
				Scope: &labelfilter.Scope{
					Condition: &labelfilter.Condition{
						Label:    "foo",
						Operator: "=",
						Value:    "bar",
					},
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		// We're expecting to see 1 result
		if len(results) != 2 {
			suite.T().Fatalf("Expected to find 2 streams in collection")
		}
		for _, result := range results {
			// Here we want to check that the result IDs are the ons from `latestResults` to make sure the latest have come back.
			if !slices.Contains(latestResults, *result.UUID) {
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
		theTime := time.Now()
		latestResult := &domain.Result{
			Result: oscaltypes113.Result{
				Title: fmt.Sprintf("Latest result"),
				End:   &theTime,
			},
			StreamID: streamId,
			Labels: map[string]string{
				"plan_id": planId.String(),
			},
		}

		// The actual latest result
		err = resultService.Create(ctx, latestResult)
		if err != nil {
			suite.T().Fatal(err)
		}

		// Create 3 older results in the stream
		for i := range 3 {
			theTime = time.Now().Add(-time.Duration(1) * time.Hour)
			err = resultService.Create(ctx, &domain.Result{
				Result: oscaltypes113.Result{
					Title: fmt.Sprintf("Older result #%d", i),
					End:   &theTime,
				},
				StreamID: streamId,
				// Older results
			})
			if err != nil {
				suite.T().Fatal(err)
			}
		}

		result, err := resultService.GetLatestResultForStream(ctx, streamId)
		if err != nil {
			suite.T().Fatal(err)
		}

		if result.UUID.String() != latestResult.UUID.String() {
			suite.T().Fatalf("Expected to find latest result in collection. Expected %v, got %v", latestResult.UUID, result.UUID)
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
		theTime := time.Now()
		latestResult := &domain.Result{
			Result: oscaltypes113.Result{
				Title: fmt.Sprintf("Latest result"),
				End:   &theTime,
			},
			StreamID: streamId,
			Labels: map[string]string{
				"plan_id": planId.String(),
			},
		}

		// The actual latest result
		err = resultService.Create(ctx, latestResult)
		if err != nil {
			suite.T().Fatal(err)
		}

		result, err := resultService.Get(ctx, latestResult.UUID)
		if err != nil {
			suite.T().Fatal(err)
		}
		if result == nil {
			suite.T().Fatalf("Expected to find result")
		}
	})
}

func (suite *ResultIntegrationSuite) TestGetIntervalledComplianceReport() {
	suite.Run("Results are correctly intervalled", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		streamId := uuid.New()
		theTime := time.Now().Add(-1 * time.Second)
		theNextTime := time.Now().Add(-6 * time.Minute) // 5 minutes later to be in next interval
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: streamId,
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theNextTime,
				},
				StreamID: streamId,
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		// The actual latest result
		intervalRecords, err := resultService.GetIntervalledComplianceReportForFilter(ctx, &labelfilter.Filter{})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Len(suite.T(), intervalRecords, 1)
		assert.Len(suite.T(), intervalRecords[0].Records, 2)
		assert.Equal(suite.T(), intervalRecords[0].ID, streamId)
		assert.Equal(suite.T(), "Res #1-#1", intervalRecords[0].Records[0].Title)
		assert.Equal(suite.T(), "Res #1-#2", intervalRecords[0].Records[1].Title)
	})
	suite.Run("Results are filled when empty", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		streamId := uuid.New()
		theTime := time.Now().Add(-1 * time.Second)
		theNextTime := time.Now().Add(-15 * time.Minute)
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#1",
					End:   &theTime,
				},
				StreamID: streamId,
			},
			domain.Result{
				UUID: newUUID(),
				Result: oscaltypes113.Result{
					Title: "Res #1-#2",
					End:   &theNextTime, // 5 minutes later to be in next interval
				},
				StreamID: streamId,
			},
		})
		if err != nil {
			suite.T().Fatal(err)
		}

		// The actual latest result
		intervalRecords, err := resultService.GetIntervalledComplianceReportForFilter(ctx, &labelfilter.Filter{})
		if err != nil {
			suite.T().Fatal(err)
		}

		assert.Len(suite.T(), intervalRecords, 1)
		assert.Len(suite.T(), intervalRecords[0].Records, 4)
	})
}
