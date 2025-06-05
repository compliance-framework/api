package service

import (
	"context"
	"sort"
	"time"

	"github.com/compliance-framework/configuration-service/internal/converters/labelfilter"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type FindingService struct {
	collection *mongo.Collection
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
func (s *FindingService) Find(ctx context.Context, filter any) ([]*Finding, error) {
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

type FindingsGroupedByControl struct {
	ControlId string    `json:"controlid" bson:"_id"`
	Findings  []Finding `json:"findings" bson:"findings"`
}

func (s *FindingService) SearchByControlClass(ctx context.Context, class string) ([]FindingsGroupedByControl, error) {
	pipeline := mongo.Pipeline{
		{{
			Key: "$addFields", Value: bson.D{
				{Key: "controlList", Value: "$controls"},
			},
		}},
		{{Key: "$unwind", Value: bson.D{
			{Key: "path", Value: "$controlList"},
			{Key: "preserveNullAndEmptyArrays", Value: true},
		}}},
		{{
			Key: "$match", Value: bson.D{
				{Key: "controlList.class", Value: class},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "controlId", Value: "$controlList.controlid"},
					{Key: "uuid", Value: "$uuid"}, // stream
				}},
				{Key: "document", Value: bson.D{ // will take last finding for stream
					{Key: "$last", Value: "$$ROOT"},
				}},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$_id.controlId"},
				{Key: "findings", Value: bson.D{{Key: "$push", Value: "$document"}}},
			},
		}},
		{{Key: "$sort", Value: bson.D{{Key: "controlid", Value: 1}}}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []FindingsGroupedByControl
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *FindingService) SearchByControlID(ctx context.Context, class string, id string) ([]*Finding, error) {
	pipeline := mongo.Pipeline{
		// Match documents related to the specific plan
		bson.D{{
			Key: "$match", Value: bson.D{
				{Key: "controls.class", Value: class},
				{Key: "controls.controlid", Value: id},
			},
		}},
		{{
			Key: "$sort", Value: bson.D{
				{Key: "uuid", Value: 1},
				{Key: "collected", Value: -1},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$uuid"},
				{Key: "latest", Value: bson.D{
					{Key: "$first", Value: "$$ROOT"},
				}},
			},
		}},
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

func (s *FindingService) ListControlClasses(ctx context.Context) ([]string, error) {
	cursor, err := s.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	uniqueClasses := make(map[string]struct{})

	for cursor.Next(ctx) {
		var finding Finding
		if err := cursor.Decode(&finding); err != nil {
			return nil, err
		}

		if finding.Controls != nil {
			for _, control := range *finding.Controls {
				uniqueClasses[control.Class] = struct{}{}
			}
		}
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	classList := make([]string, 0, len(uniqueClasses))
	for class := range uniqueClasses {
		classList = append(classList, class)
	}

	return classList, nil
}

type FindingsBySubject struct {
	SubjectID uuid.UUID `bson:"_id" json:"subject"`
	Findings  []Finding `bson:"findings" json:"findings"`
}

func (s *FindingService) SearchBySubjects(ctx context.Context, filter *labelfilter.Filter) ([]*FindingsBySubject, error) {
	//mongoFilter := labelfilter.MongoFromFilter(*filter)
	pipeline := mongo.Pipeline{
		// Match documents related to the specific plan
		//bson.D{{Key: "$match", Value: mongoFilter.GetQuery()}},
		// Sort by StreamID and End descending to get the latest result first
		{{
			Key: "$addFields", Value: bson.D{
				{Key: "subjectId", Value: "$subjectids"},
			},
		}},
		{{Key: "$unwind", Value: "$subjectId"}},

		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "subjectId", Value: "$subjectId"},
					{Key: "uuid", Value: "$uuid"},
				}},
				{Key: "document", Value: bson.D{
					{Key: "$last", Value: "$$ROOT"},
				}},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$_id.subjectId"},
				{Key: "findings", Value: bson.D{
					{Key: "$push", Value: "$document"},
				}},
			},
		}},
	}
	// Execute aggregation
	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	results := make([]*FindingsBySubject, 0)
	err = cursor.All(ctx, &results)
	if err != nil {
		return nil, err
	}

	return results, nil
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
	var times = map[time.Time]any{}
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

func (s *FindingService) GetIntervalledComplianceReportForFilter(ctx context.Context, filter *labelfilter.Filter) ([]StatusOverTimeGroup, error) {
	interval := 2 * time.Minute

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

func (s *FindingService) GetComplianceReportForControl(ctx context.Context, class string, id string) ([]StatusOverTimeRecord, error) {
	pipeline := mongo.Pipeline{
		bson.D{{
			Key: "$match", Value: bson.D{
				{Key: "controls.class", Value: class},
				{Key: "controls.controlid", Value: id},
			},
		}},
		{{
			Key: "$sort", Value: bson.D{
				{Key: "uuid", Value: 1},
				{Key: "collected", Value: -1},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: "$uuid"},
				{Key: "latest", Value: bson.D{
					{Key: "$first", Value: "$$ROOT"},
				}},
			},
		}},
		{{
			Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "status", Value: "$latest.status.state"},
				}},
				{Key: "count", Value: bson.D{
					{Key: "$sum", Value: 1},
				}},
			},
		}},
		{{
			Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "status", Value: "$_id.status"},
				{Key: "count", Value: 1},
			},
		}},
	}

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []StatusOverTimeRecord
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *FindingService) GetIntervalledComplianceReportForUUID(ctx context.Context, uuid uuid.UUID) ([]StatusOverTimeGroup, error) {
	interval := 2 * time.Minute
	intervalQuery := s.StatusOverTime(ctx, interval)
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$match", Value: bson.D{
			{Key: "uuid", Value: uuid},
		}}},
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
