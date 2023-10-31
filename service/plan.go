package service

import (
	"context"
	"errors"
	. "github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
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

func (s *PlanService) GetById(id string) (*Plan, error) {
	plan, err := mongoStore.FindById[Plan](context.Background(), "plan", id)
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (s *PlanService) Create(plan *Plan) (string, error) {
	result, err := s.planCollection.InsertOne(context.TODO(), plan)
	if err != nil {
		return "", err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *PlanService) CreateTask(planId string, task Task) (string, error) {
	// Validate the task
	if task.Title == "" {
		return "", errors.New("task title cannot be empty")
	}

	if task.Type != TaskTypeMilestone && task.Type != TaskTypeAction {
		return "", errors.New("task type must be either 'milestone' or 'action'")
	}

	task.Activities = []Activity{}

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

func (s *PlanService) CreateActivity(planId string, taskId string, activity Activity) (string, error) {
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

	var p Plan
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

func (s *PlanService) ActivatePlan(planId string) error {
	plan, err := s.GetById(planId)
	if err != nil {
		return err
	}
	plan.Status = "active"

	job := plan.JobSpecification()
	_ = s.publisher(event.PlanEvent{
		Type:             "activated",
		JobSpecification: job,
	}, event.TopicTypePlan)

	// Update the plan document and set its status to active
	pid, err := primitive.ObjectIDFromHex(planId)
	if err != nil {
		return err
	}
	filter := bson.D{{"_id", pid}}
	update := bson.M{"$set": bson.M{"status": "active"}}
	_ = s.planCollection.FindOneAndUpdate(context.Background(), filter, update)

	return nil
}

func (s *PlanService) SaveResults(planId string) error {
	panic("implement me")
}

func (s *PlanService) GetResults(planId string) ([]Result, error) {
	result, err := s.createMockData()
	if err != nil {
		return nil, err
	}
	return []Result{result}, nil
}

func (s *PlanService) createMockData() (Result, error) {
	id := primitive.NewObjectID()
	now := time.Now()
	future := now.Add(24 * time.Hour)

	property := Property{Name: "Server Type", Value: "Web Server"}
	link := Link{Href: "https://security-checks.com"}

	facet := Facet{
		Title:       "Update Frequency",
		Description: "Describes how often the system updates are checked.",
		Props:       []Property{property},
		Links:       []Link{link},
		Remarks:     "Updates are checked daily",
		Name:        "Update Check",
		Value:       "Daily",
		System:      "https://csrc.nist.gov/ns/oscal",
	}

	characterization := Characterization{
		Links:  []Link{link},
		Props:  []Property{property},
		Facets: []Facet{facet},
		Origin: Origin{Actors: []primitive.ObjectID{id}},
	}

	risk := Risk{
		Id:                id,
		Title:             "Risk due to outdated server",
		Description:       "Risk of data breach due to outdated server.",
		Props:             []Property{property},
		Links:             []Link{link},
		Remarks:           "High risk",
		Characterizations: []Characterization{characterization},
		Deadline:          future,
	}

	evidence := Evidence{
		Id:          id,
		Title:       "Screenshot of system settings",
		Description: "Screenshot showing that auto-update is enabled",
		Props:       []Property{property},
		Links:       []Link{link},
		Remarks:     "Evidence collected during system review",
	}

	observation := Observation{
		Id:          id,
		Title:       "Auto-update enabled",
		Description: "During the system configuration review, it was observed that the auto-update feature was enabled.",
		Props:       []Property{property},
		Links:       []Link{link},
		Remarks:     "Observed during system review",
		Collected:   now,
		Expires:     future,
		Evidences:   []Evidence{evidence},
	}

	finding := Finding{
		Id:                      id,
		Title:                   "Auto-update enabled",
		Description:             "The auto-update feature's activation goes against the organization's policy of manually vetting and approving system updates. This poses a potential security risk as unvetted updates could introduce vulnerabilities.",
		Props:                   []Property{property},
		Links:                   []Link{link},
		Remarks:                 "High risk finding",
		ImplementationStatement: primitive.NewObjectID(),
		Origins:                 []primitive.ObjectID{id},
		RelatedObservations:     []primitive.ObjectID{id},
		RelatedRisks:            []primitive.ObjectID{id},
		Target:                  []primitive.ObjectID{id},
	}

	localDef := LocalDefinition{Remarks: "Server is critical for operations"}

	logEntry := LogEntry{
		Timestamp:   now,
		Type:        1,
		Title:       "Review of system configuration settings",
		Description: "Started the review of system settings as per the assessment plan. No anomalies observed at this time.",
		Props:       []Property{property},
		Links:       []Link{link},
		Remarks:     "Logged by system admin",
		Start:       now,
		End:         future,
		LoggedBy:    []primitive.ObjectID{id},
	}

	attestation := Attestation{
		Parts:              []Part{{Title: "I hereby attest to the accuracy and completeness of the assessment results for the production server environment.", Props: []Property{property}, Links: []Link{link}}},
		ResponsibleParties: []primitive.ObjectID{id},
	}

	reviewedControl := ControlsAndObjectives{Title: "Server Security Control", Description: "Review of security controls in place on the server", Props: []Property{property}, Links: []Link{link}, Remarks: "All controls reviewed"}

	result := Result{
		Id:               id,
		Title:            "Security Assessment Result",
		Description:      "Results of the security assessment conducted on the production server",
		Props:            []Property{property},
		Links:            []Link{link},
		Remarks:          "Assessment completed successfully",
		LocalDefinitions: localDef,
		AssessmentLog:    []LogEntry{logEntry, logEntry, logEntry, logEntry, logEntry},
		Attestations:     []Attestation{attestation, attestation, attestation, attestation, attestation},
		Start:            now,
		End:              future,
		Findings:         []Finding{finding, finding, finding, finding, finding},
		Observations:     []Observation{observation, observation, observation, observation, observation},
		ReviewedControls: []ControlsAndObjectives{reviewedControl, reviewedControl, reviewedControl, reviewedControl, reviewedControl},
		Risks:            []Risk{risk, risk, risk, risk, risk},
	}

	return result, nil
}
