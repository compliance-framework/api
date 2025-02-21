package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/compliance-framework/configuration-service/internal/domain"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type IntervalledRecord struct {
	Title        string    `json:"title" bson:"title"`
	Interval     time.Time `json:"interval"`
	Findings     uint      `json:"findings"`
	FindingsPass uint      `json:"findings_pass" bson:"findings_pass"`
	FindingsFail uint      `json:"findings_fail" bson:"findings_fail"`
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
	fillRecord.FindingsPass = 0
	fillRecord.FindingsFail = 0
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
	if result.UUID == nil {
		id := uuid.New()
		result.UUID = &id
	}
	_, err := s.resultsCollection.InsertOne(ctx, result)
	if err != nil {
		return err
	}
	return nil
}

func (s *ResultsService) Get(ctx context.Context, id *uuid.UUID) (*domain.Result, error) {
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
			{Key: "$addFields", Value: bson.D{
				{Key: "interval", Value: bson.D{
					{Key: "$toDate", Value: bson.D{
						{Key: "$subtract", Value: bson.A{
							bson.D{{Key: "$toLong", Value: "$end"}},
							bson.D{{Key: "$mod", Value: bson.A{
								bson.D{{Key: "$subtract", Value: bson.A{
									bson.D{{Key: "$toLong", Value: "$end"}},
									bson.D{{Key: "$toLong", Value: time.Now()}},
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
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "streamId", Value: "$streamId"},
					{Key: "interval", Value: "$interval"},
				}},
				{Key: "latestRecord", Value: bson.D{
					{Key: "$last", Value: "$$ROOT"},
				}},
			}},
		},
		// Step 4: Project stage
		{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0}, // Exclude default _id
				{Key: "streamId", Value: "$_id.streamId"},
				{Key: "interval", Value: "$_id.interval"},
				{Key: "title", Value: "$latestRecord.title"},
				{Key: "findings", Value: bson.D{
					{Key: "$size", Value: bson.D{
						{Key: "$ifNull", Value: bson.A{"$latestRecord.findings", bson.A{}}},
					}},
				}},
				bson.E{
					Key: "findings_pass",
					Value: bson.D{
						{Key: "$size", Value: bson.D{
							{Key: "$ifNull", Value: bson.A{
								bson.D{{Key: "$filter", Value: bson.D{
									{Key: "input", Value: "$latestRecord.findings"},
									{Key: "as", Value: "finding"},
									{Key: "cond", Value: bson.D{
										{
											Key: "$not",
											Value: bson.D{
												{Key: "$regexMatch", Value: bson.D{
													{Key: "input", Value: "$$finding.target.status.state"},
													{Key: "regex", Value: "^satisfied"},
													{Key: "options", Value: "i"},
												}},
											},
										},
									}},
								}}},
								bson.A{},
							}},
						}},
					},
				},
				bson.E{
					Key: "findings_fail",
					Value: bson.D{
						{Key: "$size", Value: bson.D{
							{Key: "$ifNull", Value: bson.A{
								bson.D{{Key: "$filter", Value: bson.D{
									{Key: "input", Value: "$latestRecord.findings"},
									{Key: "as", Value: "finding"},
									{Key: "cond", Value: bson.D{
										{Key: "$regexMatch", Value: bson.D{
											{Key: "input", Value: "$$finding.target.status.state"},
											{Key: "regex", Value: "^satisfied"},
											{Key: "options", Value: "i"},
										}},
									}},
								}}},
								bson.A{},
							}},
						}},
					},
				},
				{Key: "observations", Value: bson.D{
					{Key: "$size", Value: bson.D{
						{Key: "$ifNull", Value: bson.A{"$latestRecord.observations", bson.A{}}},
					}},
				}},
			}},
		},
		// Step 5: Sort stage
		{
			{Key: "$sort", Value: bson.D{
				{Key: "streamId", Value: -1},
				{Key: "interval", Value: -1},
			}},
		},

		{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$streamId"},
				{Key: "records", Value: bson.D{
					{Key: "$push", Value: "$$ROOT"},
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
	}, options.Find().SetSort(bson.D{
		{Key: "end", Value: -1}, // -1 for descending order to get the latest result
	}))
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
