package service

import (
	"context"
	"github.com/compliance-framework/configuration-service/internal/service/relational"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type Heartbeat struct {
	relational.UUIDModel

	UUID      uuid.UUID `gorm:"index"`
	CreatedAt time.Time `gorm:"index"`
}

type HeartbeatService struct {
	collection *mongo.Collection
}

func NewHeartbeatService(db *mongo.Database) *HeartbeatService {
	return &HeartbeatService{
		collection: db.Collection("heartbeats"),
	}
}

func (s *HeartbeatService) getIntervalledHeartbeatPipeline(ctx context.Context, interval time.Duration) []bson.D {
	return []bson.D{
		{
			{Key: "$addFields", Value: bson.D{
				{Key: "interval", Value: bson.D{
					{Key: "$toDate", Value: bson.D{
						{Key: "$subtract", Value: bson.A{
							bson.D{{Key: "$toLong", Value: "$created"}},
							bson.D{{Key: "$mod", Value: bson.A{
								bson.D{{Key: "$subtract", Value: bson.A{
									bson.D{{Key: "$toLong", Value: "$created"}},
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
			}},
		},
		{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{
					{Key: "interval", Value: "$interval"},
				}},
				{Key: "count", Value: bson.D{
					{Key: "$sum", Value: 1},
				}},
			}},
		},
		{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0}, // Exclude default _id
				{Key: "interval", Value: "$_id.interval"},
				{Key: "count", Value: 1},
			}},
		},

		// Step 5: Sort stage
		{
			{Key: "$sort", Value: bson.D{
				{Key: "interval", Value: 1},
			}},
		},
	}
}

// HeartbeatOverTimeGroup aggregates over heartbeats and shows how many unique records were sent for that period.
type HeartbeatOverTimeGroup struct {
	Interval time.Time `bson:"interval" json:"interval"`
	Count    int64     `bson:"count" json:"count"`
}

func (s *HeartbeatService) GetIntervalledHeartbeats(ctx context.Context) ([]HeartbeatOverTimeGroup, error) {
	interval := 2 * time.Minute

	intervalQuery := s.getIntervalledHeartbeatPipeline(ctx, interval)
	pipeline := mongo.Pipeline(intervalQuery)

	cursor, err := s.collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []HeartbeatOverTimeGroup
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}

	return results, nil
}
