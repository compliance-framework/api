//go:build integration

package service

import (
	"context"
	"fmt"
	"github.com/compliance-framework/configuration-service/converters/labelfilter"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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

	suite.Run("A result can be stored with labels", func() {
		ctx := context.Background()
		resultService := NewResultsService(suite.MongoDatabase)

		planId := primitive.NewObjectID()
		result := &domain.Result{
			Title: "Result",
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
			Title: "Result",
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
		err = resultService.Create(ctx, &domain.Result{
			Title:    "Testing Result #1",
			StreamID: streamId,
			End:      time.Now(),
		})
		if err != nil {
			suite.T().Fatal(err)
		}
		err = resultService.Create(ctx, &domain.Result{
			Title:    "Testing Result #2",
			StreamID: streamId,
			End:      time.Now().Add(-time.Minute),
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: stream1,
				End:      time.Now(),
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: stream1,
				End:      time.Now().Add(-time.Minute),
			},
			domain.Result{
				Title:    "Res #2-#1",
				StreamID: stream2,
				End:      time.Now(),
			},
			domain.Result{
				Title:    "Res #2-#2",
				StreamID: stream2,
				End:      time.Now().Add(-time.Minute),
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

		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: uuid.New(),
				End:      time.Now(),
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: uuid.New(),
				End:      time.Now(),
				Labels: map[string]string{
					"foo": "baz",
				},
			},
		})

		if err != nil {
			suite.T().Fatal(err)
		}

		results, err := resultService.Search(ctx, &labelfilter.Filter{
			&labelfilter.Scope{
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: stream1,
				End:      time.Now(),
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: stream2,
				End:      time.Now(),
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: stream1,
				End:      time.Now(),
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: stream2,
				End:      time.Now(),
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: stream1,
				End:      time.Now(),
				Labels: map[string]string{
					"foo": "bar",
					"bar": "baz",
				},
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: stream2,
				End:      time.Now(),
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: stream1,
				End:      time.Now(),
				Labels: map[string]string{
					"foo": "bar",
					"bar": "baz",
				},
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: stream2,
				End:      time.Now(),
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

		// Clear out all the existing results
		_, err := suite.MongoDatabase.Collection("results").DeleteMany(ctx, bson.M{})
		if err != nil {
			suite.T().Fatal(err)
		}

		var streamId uuid.UUID
		latestResults := make([]primitive.ObjectID, 0)
		for i := range 2 {
			streamId = uuid.New()
			err = resultService.Create(ctx, &domain.Result{
				Title:    fmt.Sprintf("Older result #%d", i),
				StreamID: streamId,
				// Older result
				End: time.Now().Add(-1 * time.Hour),
				Labels: map[string]string{
					"foo": "bar",
				},
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
				// Older result
				End: time.Now(),
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
			End:      time.Now(),
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
			err = resultService.Create(ctx, &domain.Result{
				Title:    fmt.Sprintf("Older result #%d", i),
				StreamID: streamId,
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
			End:      time.Now(),
			Labels: map[string]string{
				"plan_id": planId.String(),
			},
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: streamId,
				End:      time.Now().Add(-1 * time.Second),
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: streamId,
				End:      time.Now().Add(-6 * time.Minute), // 5 minutes later to be in next interval
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
		assert.Equal(suite.T(), "Res #1-#2", intervalRecords[0].Records[0].Title)
		assert.Equal(suite.T(), "Res #1-#1", intervalRecords[0].Records[1].Title)
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
		_, err = suite.MongoDatabase.Collection("results").InsertMany(ctx, []interface{}{
			domain.Result{
				Title:    "Res #1-#1",
				StreamID: streamId,
				End:      time.Now().Add(-1 * time.Second),
			},
			domain.Result{
				Title:    "Res #1-#2",
				StreamID: streamId,
				End:      time.Now().Add(-15 * time.Minute), // 5 minutes later to be in next interval
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
