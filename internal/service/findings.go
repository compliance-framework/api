package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"sort"
	"time"
)

type FindingService struct {
	collection *mongo.Collection
}

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

// NewFindingService creates a new FindingService connected to the "findings" collection.
func NewFindingService(db *mongo.Database) *FindingService {
	return &FindingService{
		collection: db.Collection("findings"),
	}
}

// Create inserts a new finding. If the finding's ID is nil, a new UUID is generated.
// It returns the newly created finding with its ID populated.
func (s *FindingService) Create(ctx context.Context, finding *Finding) (*Finding, error) {
	if finding.ID == nil {
		id := uuid.New()
		finding.ID = &id
	}
	_, err := s.collection.InsertOne(ctx, finding)
	if err != nil {
		return nil, err
	}
	return finding, nil
}

// FindOneById retrieves a finding by its primary key (_id).
func (s *FindingService) FindOneById(ctx context.Context, id *uuid.UUID) (*Finding, error) {
	filter := bson.M{"_id": id}
	var finding Finding
	err := s.collection.FindOne(ctx, filter).Decode(&finding)
	if err != nil {
		return nil, err
	}
	return &finding, nil
}

// Find retrieves findings based on a provided filter.
func (s *FindingService) Find(ctx context.Context, filter interface{}) ([]*Finding, error) {
	cursor, err := s.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var findings []*Finding
	for cursor.Next(ctx) {
		var f Finding
		if err := cursor.Decode(&f); err != nil {
			return nil, err
		}
		findings = append(findings, &f)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

// Update replaces an existing finding document (identified by _id) with the provided finding.
// If no document matches, it returns mongo.ErrNoDocuments.
func (s *FindingService) Update(ctx context.Context, id *uuid.UUID, finding *Finding) (*Finding, error) {
	filter := bson.M{"_id": id}
	result, err := s.collection.ReplaceOne(ctx, filter, finding)
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, mongo.ErrNoDocuments
	}
	return finding, nil
}

// Delete removes a finding by its _id and returns the deleted finding.
func (s *FindingService) Delete(ctx context.Context, id *uuid.UUID, _ *Finding) (*Finding, error) {
	filter := bson.M{"_id": id}
	var deleted Finding
	err := s.collection.FindOneAndDelete(ctx, filter).Decode(&deleted)
	if err != nil {
		return nil, err
	}
	return &deleted, nil
}

// FindLatest returns the finding with the given stream UUID that has the latest Collected timestamp.
func (s *FindingService) FindLatest(ctx context.Context, streamUuid uuid.UUID) (*Finding, error) {
	filter := bson.M{"uuid": streamUuid}
	opts := options.FindOne().SetSort(bson.D{{Key: "collected", Value: -1}})
	var finding Finding
	err := s.collection.FindOne(ctx, filter, opts).Decode(&finding)
	if err != nil {
		return nil, err
	}
	return &finding, nil
}

// FindByUuid returns up to 200 findings with the specified stream UUID, ordered by Collected in descending order.
func (s *FindingService) FindByUuid(ctx context.Context, streamUuid uuid.UUID) ([]*Finding, error) {
	filter := bson.M{"uuid": streamUuid}
	opts := options.Find().SetSort(bson.D{{Key: "collected", Value: -1}}).SetLimit(200)
	cursor, err := s.collection.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var findings []*Finding
	for cursor.Next(ctx) {
		var f Finding
		if err := cursor.Decode(&f); err != nil {
			return nil, err
		}
		findings = append(findings, &f)
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func (s *FindingService) SearchByLabels(ctx context.Context, filter *labelfilter.Filter) ([]*Finding, error) {
	mongoFilter := labelfilter.MongoFromFilter(*filter)
	pipeline := mongo.Pipeline{
		// Match documents related to the specific plan
		bson.D{{Key: "$match", Value: mongoFilter.GetQuery()}},
		// Sort by StreamID and End descending to get the latest result first
		{{Key: "$sort", Value: bson.D{
			{Key: "uuid", Value: 1},       // Group by StreamID
			{Key: "collected", Value: -1}, // Latest result first
		}}},
		// Group by StreamID, taking the first document (latest due to sorting)
		{{Key: "$group", Value: bson.D{
			{Key: "_id", Value: "$uuid"}, // Group by streamId
			{Key: "latest", Value: bson.D{
				{Key: "$first", Value: "$$ROOT"}, // The latest result
			}},
		}}},
	}
	// Execute aggregation
	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	results := make([]*struct {
		UUID    uuid.UUID `bson:"_id"`
		Finding Finding   `bson:"latest"`
	}, 0)
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	output := make([]*Finding, 0)
	for _, result := range results {
		output = append(output, &result.Finding)
	}

	return output, nil
}

// StatusOverTimeRecord represents a record for a specific interval.
type StatusOverTimeRecord struct {
	Count  int    `bson:"count" json:"count"`
	Status string `bson:"status" json:"status"`
}

// StatusOverTimeGroup groups all interval records by a finding stream UUID.
type StatusOverTimeGroup struct {
	Interval time.Time              `bson:"interval" json:"interval"`
	Statuses []StatusOverTimeRecord `bson:"statuses" json:"statuses"`
}

func FillStatusOverTimeGroupGaps(ctx context.Context, statusses []StatusOverTimeGroup, duration time.Duration) []StatusOverTimeGroup {
	if len(statusses) == 0 {
		return statusses
	}

	earliestTime := statusses[0].Interval
	latestTime := statusses[0].Interval
	var times = map[time.Time]interface{}{}
	for _, record := range statusses {
		if record.Interval.Before(earliestTime) {
			earliestTime = record.Interval
		}
		if record.Interval.After(latestTime) {
			latestTime = record.Interval
		}
		times[record.Interval] = nil
	}

	fillRecord := statusses[0]
	fillRecord.Statuses = []StatusOverTimeRecord{}

	currentTime := earliestTime
	for {
		if _, ok := times[currentTime]; !ok {
			fillRecord.Interval = currentTime
			statusses = append(statusses, fillRecord)
		}
		currentTime = currentTime.Add(duration)
		if currentTime.After(latestTime) {
			break
		}
	}

	sort.Slice(statusses, func(i, j int) bool {
		return statusses[i].Interval.Before(statusses[j].Interval)
	})

	return statusses
}

// StatusOverTime aggregates the status of findings over time based on the given interval.
// It groups documents by their stream UUID and a computed "interval" (rounded based on the collected timestamp),
// then selects the latest finding in each group. Finally, it groups the intervals by UUID.
func (s *FindingService) StatusOverTime(ctx context.Context, interval time.Duration) []bson.D {
	return []bson.D{
		// Step 1: Add an "interval" field computed from "collected" timestamp.
		{{
			Key: "$addFields", Value: bson.D{
				{Key: "interval", Value: bson.D{
					{Key: "$toDate", Value: bson.D{
						{Key: "$subtract", Value: bson.A{
							bson.D{{Key: "$toLong", Value: "$collected"}},
							bson.D{{Key: "$mod", Value: bson.A{
								bson.D{{Key: "$subtract", Value: bson.A{
									bson.D{{Key: "$toLong", Value: "$collected"}},
									bson.D{{Key: "$toLong", Value: time.Now()}},
								}}},
								interval.Milliseconds(),
							}}},
						}},
					}},
				}},
			},
		}},
		// Step 2: Group by stream UUID and computed interval, taking the last record in each group.
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "uuid", Value: "$uuid"},
					{Key: "interval", Value: "$interval"},
				}},
				{Key: "latestRecord", Value: bson.D{
					{Key: "$last", Value: "$$ROOT"},
				}},
			},
		}},
		// Step 3: Project the desired fields.
		{{
			Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "uuid", Value: "$_id.uuid"},
				{Key: "interval", Value: "$_id.interval"},
				{Key: "title", Value: "$latestRecord.title"},
				{Key: "status", Value: "$latestRecord.status.state"},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "interval", Value: "$interval"},
					{Key: "status", Value: "$status"},
				}},
				{Key: "count", Value: bson.D{
					{Key: "$sum", Value: 1},
				}},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$_id.interval"},
				{Key: "statuses", Value: bson.D{
					{Key: "$push", Value: bson.D{
						{Key: "status", Value: "$_id.status"},
						{Key: "count", Value: "$count"},
					}},
				}},
			},
		}},
		{{
			Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "interval", Value: "$_id"},
				{Key: "statuses", Value: 1},
			},
		}},
		// Step 4: Sort by UUID and interval (descending).
		{{
			Key: "$sort", Value: bson.D{
				{Key: "interval", Value: 1},
			},
		}},
	}

}

func (s *FindingService) getIntervalledCompliancePipeline(ctx context.Context, interval time.Duration) []bson.D {
	return []bson.D{
		{
			{Key: "$addFields", Value: bson.D{
				{Key: "interval", Value: bson.D{
					{Key: "$toDate", Value: bson.D{
						{Key: "$subtract", Value: bson.A{
							bson.D{{Key: "$toLong", Value: "$collected"}},
							bson.D{{Key: "$mod", Value: bson.A{
								bson.D{{Key: "$subtract", Value: bson.A{
									bson.D{{Key: "$toLong", Value: "$collected"}},
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
					{Key: "uuid", Value: "$uuid"},
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
				{Key: "uuid", Value: "$_id.uuid"},
				{Key: "interval", Value: "$_id.interval"},
				{Key: "title", Value: "$latestRecord.title"},
				{Key: "findings", Value: bson.D{
					{Key: "$size", Value: bson.D{
						{Key: "$ifNull", Value: bson.A{"$latestRecord.findings", bson.A{}}},
					}},
				}},
				bson.E{
					Key: "findings_fail",
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
					Key: "findings_pass",
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
				{Key: "uuid", Value: -1},
				{Key: "interval", Value: -1},
			}},
		},

		{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$uuid"},
				{Key: "records", Value: bson.D{
					{Key: "$push", Value: "$$ROOT"},
				}},
			}},
		},
	}
}

func (s *FindingService) GetIntervalledComplianceReportForFilter(ctx context.Context, filter *labelfilter.Filter) ([]StatusOverTimeGroup, error) {
	interval := 5 * time.Minute

	mongoFilter := labelfilter.MongoFromFilter(*filter)
	intervalQuery := s.StatusOverTime(ctx, interval)
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: mongoFilter.GetQuery()}},
	}
	pipeline = append(pipeline, intervalQuery...)

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []StatusOverTimeGroup
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	results = FillStatusOverTimeGroupGaps(ctx, results, interval)

	return results, nil
}

func (s *FindingService) GetIntervalledComplianceReportForStream(ctx context.Context, streamId uuid.UUID) ([]*StreamRecords, error) {
	interval := 5 * time.Minute
	intervalQuery := s.getIntervalledCompliancePipeline(ctx, interval)
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.D{
			{Key: "uuid", Value: streamId},
		}}},
	}
	pipeline = append(pipeline, intervalQuery...)

	cursor, err := s.collection.Aggregate(ctx, pipeline)
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
		streamRecord.FillGaps(ctx, interval)
	}

	return streamRecords, nil
}
