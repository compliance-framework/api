package service

import (
	"context"
	"errors"
	"github.com/compliance-framework/configuration-service/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type IntervalledRecord struct {
	Title        string    `json:"title" bson:"title"`
	Interval     time.Time `json:"interval"`
	Findings     uint      `json:"findings"`
	Observations uint      `json:"observations"`
	HasRecords   bool      `json:"hasRecords" bson:"hasRecords"`
}

type StreamRecords struct {
	ID      uuid.UUID           `json:"_id" bson:"_id"`
	Records []IntervalledRecord `json:"records" bson:"records"`
}

func (sr *StreamRecords) FillGaps(ctx context.Context, duration time.Duration) {
	if len(sr.Records) == 0 {
		return
	}

	earliestTime := sr.Records[0].Interval
	latestTime := sr.Records[0].Interval
	var times = map[time.Time]interface{}{}
	for key, record := range sr.Records {
		sr.Records[key].HasRecords = true
		if record.Interval.Before(earliestTime) {
			earliestTime = record.Interval
		}
		if record.Interval.After(latestTime) {
			latestTime = record.Interval
		}
		times[record.Interval] = nil
	}

	fillRecord := sr.Records[0]
	fillRecord.Observations = 0
	fillRecord.Findings = 0
	fillRecord.HasRecords = false

	currentTime := earliestTime
	for {
		if _, ok := times[currentTime]; !ok {
			fillRecord.Interval = currentTime
			fillRecord.HasRecords = false
			sr.Records = append(sr.Records, fillRecord)
		}
		currentTime = currentTime.Add(duration)
		if currentTime.After(latestTime) {
			break
		}
	}
}

type ResultsService struct {
	resultsCollection *mongo.Collection
}

func NewResultsService(db *mongo.Database) *ResultsService {
	return &ResultsService{
		resultsCollection: db.Collection("results"),
	}
}

func (s *ResultsService) Create(ctx context.Context, result *domain.Result) error {
	output, err := s.resultsCollection.InsertOne(ctx, result)
	if err != nil {
		return err
	}
	insertedId, ok := output.InsertedID.(primitive.ObjectID)
	if !ok {
		return errors.New("result ID is not a primitive.ObjectID")
	}
	result.Id = &insertedId
	return nil
}

func (s *ResultsService) Get(ctx context.Context, id *primitive.ObjectID) (*domain.Result, error) {
	var result domain.Result
	err := s.resultsCollection.FindOne(ctx, bson.D{
		{Key: "_id", Value: id},
	}).Decode(&result)
	return &result, err
}

func (s *ResultsService) GetAll(ctx context.Context) ([]*domain.Result, error) {
	cursor, err := s.resultsCollection.Find(ctx, bson.D{})

	if err != nil {
		return nil, err
	}
	if cursor.Err() != nil {
		return nil, cursor.Err()
	}
	defer cursor.Close(ctx)

	var results []*domain.Result
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

func (s *ResultsService) Search(ctx context.Context, filter *labelfilter.Filter) ([]*domain.Result, error) {
	mongoFilter := labelfilter.MongoFromFilter(*filter)
	pipeline := mongo.Pipeline{
		// Match documents related to the specific plan
		bson.D{{Key: "$match", Value: mongoFilter.GetQuery()}},
		// Sort by StreamID and End descending to get the latest result first
		{{Key: "$sort", Value: bson.D{
			{Key: "streamId", Value: 1}, // Group by StreamID
			{Key: "end", Value: -1},     // Latest result first
		}}},
		// Group by StreamID, taking the first document (latest due to sorting)
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$streamId"}, // Group by streamId
			{Key: "latestResult", Value: bson.D{
				{Key: "$first", Value: "$$ROOT"}, // The latest result
			}},
		}}},
	}
	// Execute aggregation
	cursor, err := s.resultsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	results := make([]*struct {
		Id     uuid.UUID     `bson:"_id"`
		Record domain.Result `bson:"latestResult"`
	}, 0)
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	output := make([]*domain.Result, 0)
	for _, result := range results {
		output = append(output, &result.Record)
	}

	return output, nil
}

func (s *ResultsService) getIntervalledCompliancePipeline(ctx context.Context, interval time.Duration) []bson.D {
	return []bson.D{
		{
			{"$addFields", bson.D{
				{"interval", bson.D{
					{"$toDate", bson.D{
						{"$subtract", bson.A{
							bson.D{{"$toLong", "$end"}},
							bson.D{{"$mod", bson.A{
								bson.D{{"$subtract", bson.A{
									bson.D{{"$toLong", "$end"}},
									bson.D{{"$toLong", time.Now()}},
								}}},
								interval.Milliseconds(),
							}}},
						}},
					}},
				}},
			}},
		},
		// Step 3: Group stage
		{
			{"$group", bson.D{
				{"_id", bson.D{
					{"streamId", "$streamId"},
					{"interval", "$interval"},
				}},
				{"latestRecord", bson.D{
					{"$last", "$$ROOT"},
				}},
			}},
		},
		// Step 4: Project stage
		{
			{"$project", bson.D{
				{"_id", 0}, // Exclude default _id
				{"streamId", "$_id.streamId"},
				{"interval", "$_id.interval"},
				{"title", "$latestRecord.title"},
				{"findings", bson.D{
					{Key: "$size", Value: bson.D{
						{"$ifNull", bson.A{"$latestRecord.findings", bson.A{}}},
					}},
				}},
				{"observations", bson.D{
					{Key: "$size", Value: bson.D{
						{"$ifNull", bson.A{"$latestRecord.observations", bson.A{}}},
					}},
				}},
			}},
		},
		// Step 5: Sort stage
		{
			{"$sort", bson.D{
				{"streamId", -1},
				{"interval", 1},
			}},
		},

		{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$streamId"},
				{"records", bson.D{
					{"$push", "$$ROOT"},
				}},
			}},
		},
	}
}

func (s *ResultsService) GetIntervalledComplianceReportForFilter(ctx context.Context, filter *labelfilter.Filter) ([]*StreamRecords, error) {
	mongoFilter := labelfilter.MongoFromFilter(*filter)
	intervalQuery := s.getIntervalledCompliancePipeline(ctx, 5*time.Minute)
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: mongoFilter.GetQuery()}},
	}
	pipeline = append(pipeline, intervalQuery...)

	// Execute aggregation
	cursor, err := s.resultsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var streamRecords []*StreamRecords
	err = cursor.All(ctx, &streamRecords)
	if err != nil {
		return nil, err
	}

	// fill gaps in time jumps, and mark them as having zero observations and findings
	for _, streamRecord := range streamRecords {
		streamRecord.FillGaps(ctx, 5*time.Minute)
	}

	return streamRecords, nil
}

func (s *ResultsService) GetIntervalledComplianceReportForStream(ctx context.Context, streamId uuid.UUID) ([]*StreamRecords, error) {
	intervalQuery := s.getIntervalledCompliancePipeline(ctx, 5*time.Minute)
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.D{
			{Key: "streamId", Value: streamId},
		}}},
	}
	pipeline = append(pipeline, intervalQuery...)

	cursor, err := s.resultsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var streamRecords []*StreamRecords
	err = cursor.All(ctx, &streamRecords)
	if err != nil {
		return nil, err
	}

	// fill gaps in time jumps, and mark them as having zero observations and findings
	for _, streamRecord := range streamRecords {
		streamRecord.FillGaps(ctx, 5*time.Minute)
	}

	return streamRecords, nil
}

func (s *ResultsService) GetAllForStream(ctx context.Context, streamId uuid.UUID) (results []*domain.Result, err error) {
	cursor, err := s.resultsCollection.Find(ctx, bson.D{
		bson.E{Key: "streamId", Value: streamId},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	if cursor.Err() != nil {
		return nil, cursor.Err()
	}

	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (s *ResultsService) GetLatestResultForStream(ctx context.Context, streamId uuid.UUID) (*domain.Result, error) {
	// Fetch the latest result
	var result domain.Result
	err := s.resultsCollection.FindOne(ctx, bson.D{
		{Key: "streamId", Value: streamId},
	}, options.FindOne().SetSort(bson.D{
		{Key: "end", Value: -1}, // -1 for descending order to get the latest result
	})).Decode(&result)
	return &result, err
}

func (s *ResultsService) GetLatestResultsForPlan(ctx context.Context, plan *domain.Plan) ([]*domain.Result, error) {

	mongoFilter := labelfilter.MongoFromFilter(plan.ResultFilter)
	// Aggregation pipeline
	pipeline := mongo.Pipeline{
		// Match documents related to the specific plan
		bson.D{{Key: "$match", Value: mongoFilter.GetQuery()}},
		// Sort by StreamID and End descending to get the latest result first
		{{Key: "$sort", Value: bson.D{
			{Key: "streamId", Value: 1}, // Group by StreamID
			{Key: "end", Value: -1},     // Latest result first
		}}},
		// Group by StreamID, taking the first document (latest due to sorting)
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$streamId"}, // Group by streamId
			{Key: "latestResult", Value: bson.D{
				{Key: "$first", Value: "$$ROOT"}, // The latest result
			}},
		}}},
	}

	// Execute aggregation
	cursor, err := s.resultsCollection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	results := make([]*struct {
		Id     uuid.UUID     `bson:"_id"`
		Record domain.Result `bson:"latestResult"`
	}, 0)
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	output := make([]*domain.Result, 0)
	for _, result := range results {
		output = append(output, &result.Record)
	}

	return output, nil
}
