package service

import (
	"context"
	"errors"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlanService struct {
	planCollection *mongo.Collection
	publisher      event.Publisher
}

func NewPlanService(p event.Publisher) *PlanService {
	return &PlanService{
		planCollection: mongoStore.Collection("plan"),
		publisher:      p,
	}
}

func (s *PlanService) GetById(id string) (*domain.Plan, error) {
	plan, err := mongoStore.FindById[domain.Plan](context.Background(), "plan", id)
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (s *PlanService) Create(plan *domain.Plan) (string, error) {
	result, err := s.planCollection.InsertOne(context.TODO(), plan)
	if err != nil {
		return "", err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *PlanService) CreateTask(planId string, task domain.Task) (string, error) {
	// Validate the task
	if task.Title == "" {
		return "", errors.New("task title cannot be empty")
	}

	if task.Type != domain.TaskTypeMilestone && task.Type != domain.TaskTypeAction {
		return "", errors.New("task type must be either 'milestone' or 'action'")
	}

	task.Activities = []domain.Activity{}

	pid, err := primitive.ObjectIDFromHex(planId)
	if err != nil {
		return "", err
	}
	task.Id = primitive.NewObjectID()
	filter := bson.D{{"_id", pid}}

	update := bson.M{
		"$push": bson.M{
			"tasks": task,
		},
	}
	_ = s.planCollection.FindOneAndUpdate(context.Background(), filter, update)
	if err != nil {
		return "", err
	}

	return task.Id.Hex(), nil
}

func (s *PlanService) CreateActivity(planId string, taskId string, activity domain.Activity) (string, error) {
	pid, err := primitive.ObjectIDFromHex(planId)
	if err != nil {
		return "", err
	}
	tid, err := primitive.ObjectIDFromHex(taskId)
	if err != nil {
		return "", err
	}

	activity.Id = primitive.NewObjectID()
	filter := bson.D{{"_id", pid}, {"tasks.id", tid}}

	var p domain.Plan
	err = s.planCollection.FindOne(context.Background(), filter).Decode(&p)
	if err != nil {
		return "", err
	}

	update := bson.M{
		"$push": bson.M{
			"tasks.0.activities": activity,
		},
	}
	_ = s.planCollection.FindOneAndUpdate(context.Background(), filter, update)
	if err != nil {
		return "", err
	}

	return activity.Id.Hex(), nil
}

func (s *PlanService) SetSubjectsForActivity(taskId string, planId string, activityId string, subject domain.SubjectSelection) error {
	pid, _ := primitive.ObjectIDFromHex(planId)
	tid, _ := primitive.ObjectIDFromHex(taskId)

	filter := bson.D{{"_id", pid}, {"tasks.id", tid}}
	update := bson.D{{"$set", bson.D{{"tasks.$.subject", subject}}}}
	_, err := s.planCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	return nil
}

func (s *PlanService) Update(plan *domain.Plan) error {
	_, err := s.planCollection.ReplaceOne(context.Background(), bson.D{{"_id", plan.Id}}, plan)
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	jobSpec, err := plan.JobSpecification()
	if err != nil {
		return err
	}

	if plan.Ready() {
		published := event.PlanPublished{
			JobSpecification: jobSpec,
		}
		err = s.publisher(published, event.TopicTypePlan)
		if err != nil {
			return err
		}
	}

	return nil
}
