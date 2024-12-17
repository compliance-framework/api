package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	. "github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	mongoStore "github.com/compliance-framework/configuration-service/store/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type PlanService struct {
	planCollection    *mongo.Collection
	subjectCollection *mongo.Collection
	publisher         event.Publisher
}

func NewPlanService(p event.Publisher) *PlanService {
	return &PlanService{
		planCollection:    mongoStore.Collection("plan"),
		subjectCollection: mongoStore.Collection("subject"),
		publisher:         p,
	}
}

func (s *PlanService) GetById(id string) (*Plan, error) {
	log.Println("GetById")
	log.Println("id: ", id)
	plan, err := mongoStore.FindById[Plan](context.Background(), "plan", id)
	if err != nil {
		return nil, err
	}
	return &plan, nil
}

func (s *PlanService) Create(plan *Plan) (string, error) {
	log.Println("Create")
	result, err := s.planCollection.InsertOne(context.TODO(), plan)
	if err != nil {
		return "", err
	}
	return result.InsertedID.(primitive.ObjectID).Hex(), nil
}

func (s *PlanService) CreateTask(planId string, task Task) (string, error) {
	log.Println("CreateTask")
	log.Println("planId: ", planId)
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
	filter := bson.D{bson.E{Key: "_id", Value: pid}}

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
	log.Println("CreateActivity")
	log.Println("planId: ", planId)
	log.Println("taskId: ", taskId)
	pid, err := primitive.ObjectIDFromHex(planId)
	if err != nil {
		return "", err
	}
	tid, err := primitive.ObjectIDFromHex(taskId)
	if err != nil {
		return "", err
	}

	activity.Id = primitive.NewObjectID()
	filter := bson.D{bson.E{Key: "_id", Value: pid}, bson.E{Key: "tasks.id", Value: tid}}

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
	log.Println("ActivatePlan")
	log.Println("planId: ", planId)
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
	filter := bson.D{bson.E{Key: "_id", Value: pid}}
	update := bson.M{"$set": bson.M{"status": "active"}}
	_ = s.planCollection.FindOneAndUpdate(context.Background(), filter, update)

	return nil
}

func (s *PlanService) SaveResult(planId string, result Result) error {
	log.Println("SaveResult")
	log.Println("planId: ", planId)
	pid, err := primitive.ObjectIDFromHex(planId)
	if err != nil {
		return err
	}
	filter := bson.D{bson.E{Key: "_id", Value: pid}}

	// find a doc with the filter
	var p Plan
	err = s.planCollection.FindOne(context.Background(), filter).Decode(&p)
	if err != nil {
		return err
	}

	update := bson.M{
		"$push": bson.M{
			"results": result,
		},
	}
	_ = s.planCollection.FindOneAndUpdate(context.Background(), filter, update)
	if err != nil {
		return err
	}

	return nil
}

func (s *PlanService) SaveSubject(subject Subject) error {
	log.Println("SaveSubject")
	_, err := s.subjectCollection.InsertOne(context.Background(), subject)
	if err != nil {
		return err
	}
	return nil
}

func (s *PlanService) Findings(planId string, resultId string) ([]bson.M, error) {
	log.Println("Findings", "planId: ", planId, "resultId: ", resultId)

	var pipeline mongo.Pipeline
	var results []bson.M

	// Check if planId or resultId is provided
	if planId != "any" && planId != "" {
		pid, err := primitive.ObjectIDFromHex(planId)
		if err != nil {
			return nil, fmt.Errorf("invalid planId: %v", err)
		}
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: bson.M{"_id": pid}}})
	}
	if resultId != "any" && resultId != "" {
		rid, err := primitive.ObjectIDFromHex(resultId)
		if err != nil {
			return nil, fmt.Errorf("invalid resultId: %v", err)
		}
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: bson.M{"results.id": rid}}})
	}

	pipeline = append(pipeline,
		bson.D{{"$unwind", bson.D{{"path", "$results"}}}},
	)
	pipeline = append(pipeline,
		bson.D{{"$sort", bson.D{{"results.end", 1}}}},
	)
	pipeline = append(pipeline,
		bson.D{{"$unwind", bson.D{{"path", "$results.findings"}}}},
	)

	pipeline = append(pipeline,
		bson.D{{"$project", bson.D{
			{"_id", "$results.findings._id"},
			{"title", "$results.findings.title"},
			{"description", "$results.findings.description"},
			{"remarks", "$results.findings.remarks"},
			{"resultEnd", "$results.end"},
		}}},
	)

	cursor, err := s.planCollection.Aggregate(context.Background(), pipeline)
	if err != nil {
		return nil, err
	}

	if err = cursor.All(context.Background(), &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *PlanService) Observations(planId string, resultId string) ([]bson.M, error) {
	log.Println("Observations ", "planId: ", planId, ", resultId: ", resultId)

	var pipeline mongo.Pipeline

	// Check if planId or resultId is provided
	if planId != "any" && planId != "" {
		pid, err := primitive.ObjectIDFromHex(planId)
		if err != nil {
			return nil, fmt.Errorf("invalid planId: %v", err)
		}
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: bson.M{"_id": pid}}})
	}
	if resultId != "any" && resultId != "" {
		rid, err := primitive.ObjectIDFromHex(resultId)
		if err != nil {
			return nil, fmt.Errorf("invalid resultId: %v", err)
		}
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: bson.M{"results.id": rid}}})
	}

	pipeline = append(pipeline,
		bson.D{{"$unwind", bson.D{{"path", "$results"}}}},
	)
	pipeline = append(pipeline,
		bson.D{{"$sort", bson.D{{"results.observations.collected", 1}}}},
	)
	pipeline = append(pipeline,
		bson.D{{"$unwind", bson.D{{"path", "$results.observations"}}}},
	)

	pipeline = append(pipeline, bson.D{
		{"$project", bson.D{
			{Key: "_id", Value: "$results.observations._id"},
			{Key: "title", Value: "$results.observations.title"},
			{Key: "description", Value: "$results.observations.description"},
			{Key: "collected", Value: "$results.observations.collected"},
			{Key: "props", Value: "$results.observations.props"},
		}},
	})

	cursor, err := s.planCollection.Aggregate(context.Background(), pipeline)
	if err != nil {
		return nil, err
	}

	var results []bson.M
	if err = cursor.All(context.Background(), &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *PlanService) Risks(planId string, resultId string) ([]Risk, error) {
	log.Println("Risks", "planId: ", planId, "resultId: ", resultId)
	pipeline := bson.A{
		bson.D{{Key: "$unwind", Value: bson.D{{Key: "path", Value: "$tasks"}}}},
		bson.D{
			{Key: "$project",
				Value: bson.D{
					{Key: "_id", Value: 0},
				},
			},
		},
	}

	cursor, err := s.planCollection.Aggregate(context.Background(), pipeline)
	if err != nil {
		return nil, err
	}

	var risks []Risk
	if err = cursor.All(context.Background(), &risks); err != nil {
		return nil, err
	}

	return risks, nil
}

type RiskSeverity string

const (
	Medium RiskSeverity = "medium"
	Low    RiskSeverity = "low"
	High   RiskSeverity = "high"
)

type RiskState string

const (
	Pass          RiskState = "pass"
	Warn          RiskState = "warn"
	Fail          RiskState = "fail"
	Indeterminate RiskState = "indeterminate"
)

type RiskLevels struct {
	Low    int `json:"low" yaml:"low"`
	Medium int `json:"medium" yaml:"medium"`
	High   int `json:"high" yaml:"high"`
}

type RiskScore struct {
	Score    int          `json:"score" yaml:"score"`
	Severity RiskSeverity `json:"severity" yaml:"severity"`
}

type PlanSummary struct {
	Published        string     `json:"published" yaml:"published"`
	EndDate          string     `json:"endDate" yaml:"endDate"`
	Description      string     `json:"description" yaml:"description"`
	Status           string     `json:"status" yaml:"status"`
	NumControls      int        `json:"numControls" yaml:"numControls"`
	NumSubjects      int        `json:"numSubjects" yaml:"numSubjects"`
	NumObservations  int        `json:"numObservations" yaml:"numObservations"`
	NumRisks         int        `json:"numRisks" yaml:"numRisks"`
	RiskScore        RiskScore  `json:"riskScore" yaml:"riskScore"`
	ComplianceStatus float64    `json:"complianceStatus" yaml:"complianceStatus"`
	RiskLevels       RiskLevels `json:"riskLevels" yaml:"riskLevels"`
}

type ComplianceStatusByTargets struct {
	Control    string      `json:"control" yaml:"control"`
	Target     string      `json:"target" yaml:"target"`
	Compliance []RiskState `json:"compliance" yaml:"compliance"`
}

type ComplianceStatusOverTime struct {
	Date         string `json:"date" yaml:"date"`
	Findings     int    `json:"findings" yaml:"findings"`
	Observations int    `json:"observations" yaml:"observations"`
	Risks        int    `json:"risks" yaml:"risks"`
}

type RemediationVsTime struct {
	Control     string `json:"control" yaml:"control"`
	Remediation string `json:"remediation" yaml:"remediation"`
}

func (s *PlanService) ResultSummary(planId string, resultId string) (PlanSummary, error) {
	log.Println("ResultSummary")
	log.Println("planId: ", planId)
	log.Println("resultId: ", resultId)
	// Since we don't have all the data in place, this is definitely temporary (not a real query either).
	// TODO: We should Look for specific Plan and Results here. First Value only for Demonstration with Mocked values.
	var p Plan
	err := s.planCollection.FindOne(context.Background(), bson.D{}).Decode(&p)
	if err != nil {
		return PlanSummary{}, err
	}

	return PlanSummary{
		Published:       "2022-12-01T00:00:00Z",
		EndDate:         "2022-12-31T23:59:59Z",
		Description:     p.Title,
		Status:          "Completed",
		NumControls:     50,
		NumSubjects:     10,
		NumObservations: 30,
		NumRisks:        5,
		RiskScore: RiskScore{
			Score:    75,
			Severity: "medium",
		},
		ComplianceStatus: 0.67,
		RiskLevels: RiskLevels{
			Low:    2,
			Medium: 2,
			High:   1,
		},
	}, nil
}

func (s *PlanService) ComplianceStatusByTargets(planId string, resultId string) ([]ComplianceStatusByTargets, error) {
	log.Println("ComplianceStatusByTargets")
	log.Println("planId: ", planId)
	log.Println("resultId: ", resultId)
	// TODO: this is hard-coded for demo purposes only at the moment.
	// var p Plan
	// err := s.planCollection.FindOne(context.Background(), bson.D{{Key: "_id", Value: planId}}).Decode(&p)
	// if err != nil {
	//  	return []ComplianceStatusByTargets{}, err
	// }

	return []ComplianceStatusByTargets{
		{
			Control:    "Server Security Control",
			Target:     "Production Server",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "warn", "pass", "pass", "fail"},
		},
		{
			Control:    "Database Integrity Control",
			Target:     "Main Database",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "fail", "pass", "pass", "fail"},
		},
		{
			Control:    "Network Access Control",
			Target:     "Corporate Network",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "fail", "pass", "pass", "fail"},
		},
		{
			Control:    "Data Encryption Standard",
			Target:     "User Data Store",
			Compliance: []RiskState{"pass", "fail", "warn", "pass", "fail", "pass", "pass", "fail"},
		},
		{
			Control:    "Application Security Protocol",
			Target:     "Customer Facing App",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "fail", "pass", "pass", "warn"},
		},
		{
			Control:    "Firewall Configuration",
			Target:     "Internal Network",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "fail", "pass", "pass", "fail"},
		},
		{
			Control:    "Physical Security Measures",
			Target:     "Data Center",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "fail", "pass", "pass", "fail"},
		},
		{
			Control:    "User Authentication System",
			Target:     "Employee Portal",
			Compliance: []RiskState{"pass", "fail", "indeterminate", "pass", "fail", "pass", "pass", "fail"},
		},
	}, nil
}

func (s *PlanService) ComplianceOverTime(planId string, resultId string) ([]bson.M, error) {
	// This is grouped by minute for now, but the granularity could be calculated or specified by the client.
	var pipeline mongo.Pipeline

	log.Println("ComplianceOverTime")
	log.Println("planId: ", planId)

	// Check if planId is provided
	if planId != "any" && planId != "" {
		pid, err := primitive.ObjectIDFromHex(planId)
		if err != nil {
			return nil, fmt.Errorf("invalid planId: %v", err)
		}
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: bson.M{"_id": pid}}})
	}

	if resultId != "any" && resultId != "" {
		rid, err := primitive.ObjectIDFromHex(resultId)
		if err != nil {
			return nil, fmt.Errorf("invalid resultId: %v", err)
		}
		pipeline = append(pipeline, bson.D{{Key: "$match", Value: bson.M{"results.id": rid}}})
	}

	pipeline = append(pipeline, bson.D{{Key: "$unwind", Value: "$results"}})
	pipeline = append(pipeline, bson.D{{Key: "$project", Value: bson.M{
		"_id": 0,
		"date": bson.M{
			"$dateToString": bson.M{
				"format": "%Y-%m-%dT%H:%M:00Z",
				"date":   "$results.start",
			},
		},
		"findings": bson.M{
			"$size": bson.M{
				"$ifNull": bson.A{"$results.findings", bson.A{}},
			},
		},
		"observations": bson.M{
			"$size": bson.M{
				"$ifNull": bson.A{"$results.observations", bson.A{}},
			},
		},
		"risks": bson.M{
			"$size": bson.M{
				"$ifNull": bson.A{"$results.risks", bson.A{}},
			},
		},
	}}},
	)

	pipeline = append(pipeline, bson.D{
		{Key: "$group", Value: bson.M{
			"_id":               "$date",
			"totalFindings":     bson.M{"$sum": "$findings"},
			"totalObservations": bson.M{"$sum": "$observations"},
			"totalRisks":        bson.M{"$sum": "$risks"},
		}},
	})

	pipeline = append(pipeline, bson.D{
		{Key: "$sort", Value: bson.M{
			"_id": 1, // 1 for ascending order, -1 for descending order
		}},
	})

	pipeline = append(pipeline, bson.D{
		{Key: "$project", Value: bson.M{
			"_id":               0,
			"minute":            "$_id",
			"totalFindings":     1,
			"totalObservations": 1,
			"totalRisks":        1,
		}},
	})

	cursor, err := s.planCollection.Aggregate(context.Background(), pipeline)
	if err != nil {
		return nil, err
	}

	var results []bson.M
	if err = cursor.All(context.Background(), &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *PlanService) RemediationVsTime(planId string, resultId string) ([]RemediationVsTime, error) {
	log.Println("RemediationVsTime")
	log.Println("planId: ", planId)
	log.Println("resultId: ", resultId)
	return []RemediationVsTime{
		{
			Control:     "Server Security Control",
			Remediation: "3 days",
		},
		{
			Control:     "Database Integrity Control",
			Remediation: "1 day",
		},
		{
			Control:     "Network Access Control",
			Remediation: "2 days",
		},
		{
			Control:     "Data Encryption Standard",
			Remediation: "1 day",
		},
		{
			Control:     "Application Security Protocol",
			Remediation: "3 days",
		},
		{
			Control:     "Firewall Configuration",
			Remediation: "1 day",
		},
		{
			Control:     "Physical Security Measures",
			Remediation: "1 day",
		},
		{
			Control:     "User Authentication System",
			Remediation: "2 days",
		},
	}, nil
}

func (s *PlanService) Results(planId string) ([]bson.M, error) {
	// TODO: order by date
	// TODO: use planId
	log.Println("Results", "planId:", planId)
	pipeline := mongo.Pipeline{
		bson.D{{Key: "$project", Value: bson.D{
			{Key: "_id", Value: 0},
			{Key: "results", Value: 1},
		}}},
		bson.D{{Key: "$unwind", Value: "$results"}},
		bson.D{{Key: "$replaceRoot", Value: bson.D{{Key: "newRoot", Value: "$results"}}}},
	}

	cursor, err := s.planCollection.Aggregate(context.Background(), pipeline)
	if err != nil {
		return nil, err
	}

	var results []bson.M
	if err = cursor.All(context.Background(), &results); err != nil {
		return nil, err
	}

	return results, nil

}
