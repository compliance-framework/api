package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	oscal "github.com/compliance-framework/configuration-service/internal/models/oscal/v1_1"
	models "github.com/compliance-framework/configuration-service/internal/models/runtime"
	"github.com/compliance-framework/configuration-service/internal/pubsub"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type RuntimeJobCreator struct {
	confCreated <-chan pubsub.Event
	confUpdated <-chan pubsub.Event
	confDeleted <-chan pubsub.Event
	Log         *zap.SugaredLogger
	Driver      storeschema.Driver
}

func (r *RuntimeJobCreator) Init() error {
	c, err := pubsub.Subscribe(pubsub.RuntimeConfigurationCreated)
	if err != nil {
		return err
	}
	r.confCreated = c
	c, err = pubsub.Subscribe(pubsub.RuntimeConfigurationUpdated)
	if err != nil {
		return err
	}
	r.confUpdated = c
	c, err = pubsub.Subscribe(pubsub.RuntimeConfigurationDeleted)
	if err != nil {
		return err
	}
	r.confDeleted = c
	return nil
}

func (r *RuntimeJobCreator) Run() {
	for {
		select {
		case msg := <-r.confCreated:
			err := r.createJobs(msg)
			if err != nil {
				r.Log.Errorf("could not create ConfigurationJobs from RuntimeConfiguration: %w", err)
			}
		case msg := <-r.confUpdated:
			err := r.updateJobs(msg)
			if err != nil {
				r.Log.Errorf("could not update ConfigurationJobs from RuntimeConfiguration: %w", err)
			}
		case msg := <-r.confDeleted:
			err := r.deleteJobs(msg)
			if err != nil {
				r.Log.Errorf("could not update ConfigurationJobs from RuntimeConfiguration: %w", err)
			}
		}
	}
}

// TODO Add tests
func (r *RuntimeJobCreator) createJobs(msg pubsub.Event) error {
	jobs := make([]*models.RuntimeConfigurationJob, 0)
	r.Log.Infow("creating jobs from RuntimeConfiguration", "msg", msg)
	d, err := json.Marshal(msg.Data)
	if err != nil {
		return fmt.Errorf("could not marshal data")
	}
	config := &models.RuntimeConfiguration{}
	err = config.FromJSON(d)
	if err != nil {
		return fmt.Errorf("could not load data")
	}
	ap := oscal.AssessmentPlan{}
	err = r.Driver.Get(context.Background(), ap.Type(), config.AssessmentPlanUuid, &ap)
	if err != nil {
		return fmt.Errorf("no assessment-plan with uuid %v found: %w", config.AssessmentPlanUuid, err)
	}
	task := &oscal.Task{}
	for i, t := range ap.Tasks {
		if t.Uuid == config.TaskUuid {
			task = ap.Tasks[i]
			break
		}
	}
	if task.Uuid != config.TaskUuid {
		return fmt.Errorf("task with uuid %v not found on assessment-plan %v", config.TaskUuid, config.AssessmentPlanUuid)
	}
	for _, activity := range task.AssociatedActivities {
		for _, subject := range activity.Subjects {
			for _, include := range subject.IncludeSubjects {
				job := &models.RuntimeConfigurationJob{
					ConfigurationUuid: config.Uuid,
					ActivityId:        activity.ActivityUuid,
					SubjectUuid:       include.SubjectUuid,
					SubjectType:       include.Type.(string),
					Schedule:          config.Schedule,
					Plugins:           config.Plugins,
				}
				jobs = append(jobs, job)
			}
		}
	}
	create := make(map[string]interface{})
	for i := range jobs {
		uid, err := uuid.NewUUID()
		if err != nil {
			return fmt.Errorf("failed generating uid for job: %w", err)
		}
		jobs[i].Uuid = uid.String()
		create[uid.String()] = jobs[i]
	}
	t := &models.RuntimeConfigurationJob{}
	r.Log.Infow("will create jobs", "jobs", jobs)
	err = r.Driver.CreateMany(context.Background(), t.Type(), create)
	return err
}

// TODO Make better logic, as this will override any runtime-uuid that is setup via assignJobs
func (r *RuntimeJobCreator) updateJobs(msg pubsub.Event) error {
	err := r.deleteJobs(msg)
	if err != nil {
		return fmt.Errorf("could not delete jobs as part of an update: %w", err)
	}
	err = r.createJobs(msg)
	if err != nil {
		return fmt.Errorf("could not create jobs as part of an update: %w", err)
	}
	return nil
}

// TODO Add tests
func (r *RuntimeJobCreator) deleteJobs(msg pubsub.Event) error {
	r.Log.Infow("deleting jobs from RuntimeConfiguration", "msg", msg)
	d, err := json.Marshal(msg.Data)
	if err != nil {
		return fmt.Errorf("could not marshal data")
	}
	config := &models.RuntimeConfiguration{}
	job := &models.RuntimeConfigurationJob{}
	err = config.FromJSON(d)
	if err != nil {
		return fmt.Errorf("could not load data")
	}
	conditions := map[string]interface{}{
		"configurationuuid": config.Uuid,
	}
	err = r.Driver.DeleteWhere(context.Background(), "jobs", job, conditions)
	return err
}
