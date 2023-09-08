package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	oscal "github.com/compliance-framework/configuration-service/internal/models/oscal/v1_1"
	"github.com/compliance-framework/configuration-service/internal/models/runtime"
	models "github.com/compliance-framework/configuration-service/internal/models/runtime"
	"github.com/compliance-framework/configuration-service/internal/pubsub"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TODO Instead of having this runtime to publish changes, it would be better to have the Driver to publish changes whenever that change happened (with a specific message, and a specific channel)
type RuntimeJobCreator struct {
	confCreated <-chan pubsub.Event
	confUpdated <-chan pubsub.Event
	confDeleted <-chan pubsub.Event
	Log         *zap.SugaredLogger
	Driver      storeschema.Driver
}

func (r *RuntimeJobCreator) Init() error {
	c, err := pubsub.Subscribe(pubsub.ObjectCreated)
	if err != nil {
		return err
	}
	r.confCreated = c
	c, err = pubsub.Subscribe(pubsub.ObjectUpdated)
	if err != nil {
		return err
	}
	r.confUpdated = c
	c, err = pubsub.Subscribe(pubsub.ObjectDeleted)
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

func (r *RuntimeJobCreator) createJobs(msg pubsub.Event) error {
	evt := msg.Data.(pubsub.DatabaseEvent)
	c := models.RuntimeConfiguration{}
	// skip events that are not runtimeConfiguration changes
	if evt.Type != c.Type() {
		return nil
	}
	jobs := make([]*models.RuntimeConfigurationJob, 0)
	r.Log.Infow("creating jobs from RuntimeConfiguration", "msg", msg)
	d, err := json.Marshal(evt.Object)
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
	baseParams := []*models.RuntimeParameters{}
	for _, v := range task.Props {
		param := models.RuntimeParameters{
			Name:  v.Name,
			Value: v.Value,
		}
		baseParams = append(baseParams, &param)
	}

	for _, activity := range task.AssociatedActivities {
		params := []*models.RuntimeParameters{}
		params = append(params, baseParams...)
		// Including Activities Props into Parameters.
		// TODO - INCLUDE COMPONENT PROPERTIES
		if ap.LocalDefinitions == nil {
			return fmt.Errorf("no local definitions to get associated activities.")
		}
		valid := false
		for _, v := range ap.LocalDefinitions.Activities {
			if v.Uuid == activity.ActivityUuid {
				valid = true
				for _, p := range v.Props {
					param := models.RuntimeParameters{
						Name:  p.Name,
						Value: p.Value,
					}
					params = append(params, &param)
				}
			}
		}
		if !valid {
			return fmt.Errorf("associated activity %v not found in assessment plan %v", activity.ActivityUuid, config.AssessmentPlanUuid)
		}
		job := &models.RuntimeConfigurationJob{
			ConfigurationUuid: config.Uuid,
			TaskUuid:          task.Uuid,
			AssessmentId:      ap.Uuid,
			Parameters:        params,
			ActivityId:        activity.ActivityUuid,
			RuntimeUuid:       config.RuntimeUuid,
			TargetSubjects:    config.TargetSubjects,
			Schedule:          config.Schedule,
			Plugins:           config.Plugins,
		}
		jobs = append(jobs, job)
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
	if err != nil {
		return fmt.Errorf("could not create jobs: %w", err)
	}
	for _, job := range jobs {
		event := runtime.RuntimeConfigurationJobPayload{
			Topic: fmt.Sprintf("runtime.configuration.%v", job.RuntimeUuid),
			RuntimeConfigurationEvent: runtime.RuntimeConfigurationEvent{
				Data: job,
				Type: runtime.PayloadEventCreated,
				Uuid: job.Uuid,
			},
		}
		pubsub.PublishPayload(event)
	}
	return nil
}

// TODO Make logic better. Too much of a convolution, too many responsibilities
// TODO Add OnChange mechanism to listen for assessment-plan changes.
func (r *RuntimeJobCreator) updateJobs(msg pubsub.Event) error {
	evt := msg.Data.(pubsub.DatabaseEvent)
	c := models.RuntimeConfiguration{}
	// skip events that are not runtimeConfiguration changes
	if evt.Type != c.Type() {
		return nil
	}
	d, err := json.Marshal(evt.Object)
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
	// TODO - If the assessmentplan is invalid, instead we should delete all the jobs associated to this assessment plan.
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
	// TODO - If the Task uuid is invalid, instead we should delete all the jobs containing refering to this task.
	if task.Uuid != config.TaskUuid {
		return fmt.Errorf("task with uuid %v not found on assessment-plan %v", config.TaskUuid, config.AssessmentPlanUuid)
	}
	baseParams := []*models.RuntimeParameters{}
	for _, v := range task.Props {
		param := models.RuntimeParameters{
			Name:  v.Name,
			Value: v.Value,
		}
		baseParams = append(baseParams, &param)
	}
	j := &models.RuntimeConfigurationJob{}
	filter := map[string]interface{}{
		"configuration-uuid": config.Uuid,
	}
	jobs, err := r.Driver.GetAll(context.Background(), j.Type(), j, filter)
	if err != nil {
		return fmt.Errorf("could not get all jobs: %w", err)
	}
	t := map[string]*models.RuntimeConfigurationJob{}
	for _, jj := range jobs {
		job := jj.(*models.RuntimeConfigurationJob)
		key := job.ActivityId
		t[key] = job
	}
	o := map[string]*models.RuntimeConfigurationJob{}
	for _, activity := range task.AssociatedActivities {
		k := activity.ActivityUuid
		o[k] = &models.RuntimeConfigurationJob{
			ActivityId: activity.ActivityUuid,
		}
	}
	// Remove uneeded Jobs
	for k, v := range t {
		if _, ok := o[k]; !ok {
			err = r.Driver.Delete(context.Background(), j.Type(), v.Uuid)
			if err != nil {
				return fmt.Errorf("could not delete job %v: %w", v.Uuid, err)
			}
			delete(t, k)
			// Job no longer needed - pub it to propagate unassign from runtime
			event := runtime.RuntimeConfigurationJobPayload{
				Topic: fmt.Sprintf("runtime.configuration.%v", v.RuntimeUuid),
				RuntimeConfigurationEvent: runtime.RuntimeConfigurationEvent{
					Data: nil,
					Type: runtime.PayloadEventDeleted,
					Uuid: v.Uuid,
				},
			}
			pubsub.PublishPayload(event)
		}
	}

	for k := range o {
		_, ok := t[k]
		params := []*models.RuntimeParameters{}
		params = append(params, baseParams...)
		for _, v := range ap.LocalDefinitions.Activities {
			if v.Uuid == k {
				for _, p := range v.Props {
					param := models.RuntimeParameters{
						Name:  p.Name,
						Value: p.Value,
					}
					params = append(params, &param)
				}
			}
		}
		// Create New Jobs
		if !ok {
			job := &models.RuntimeConfigurationJob{
				ConfigurationUuid: config.Uuid,
				TaskUuid:          task.Uuid,
				AssessmentId:      ap.Uuid,
				Parameters:        params,
				ActivityId:        k,
				RuntimeUuid:       config.RuntimeUuid,
				TargetSubjects:    config.TargetSubjects,
				Schedule:          config.Schedule,
				Plugins:           config.Plugins,
			}
			err = r.Driver.Create(context.Background(), j.Type(), job.Uuid, job)
			if err != nil {
				return fmt.Errorf("could not create job %v: %w", job.Uuid, err)
			}
			event := runtime.RuntimeConfigurationJobPayload{
				Topic: fmt.Sprintf("runtime.configuration.%v", job.RuntimeUuid),
				RuntimeConfigurationEvent: runtime.RuntimeConfigurationEvent{
					Data: job,
					Type: runtime.PayloadEventCreated,
					Uuid: job.Uuid,
				},
			}
			pubsub.PublishPayload(event)

		} else {
			// Updates that need to be propagated
			t[k].Schedule = config.Schedule
			t[k].Plugins = config.Plugins
			t[k].Parameters = params
			err = r.Driver.Update(context.Background(), j.Type(), t[k].Uuid, t[k])
			if err != nil {
				return fmt.Errorf("could not update job %v: %w", t[k].Uuid, err)
			}
			event := runtime.RuntimeConfigurationJobPayload{
				Topic: fmt.Sprintf("runtime.configuration.%v", t[k].RuntimeUuid),
				RuntimeConfigurationEvent: runtime.RuntimeConfigurationEvent{
					Data: t[k],
					Type: runtime.PayloadEventUpdated,
					Uuid: t[k].Uuid,
				},
			}
			pubsub.PublishPayload(event)
		}
	}
	return nil
}

// TODO Add tests
func (r *RuntimeJobCreator) deleteJobs(msg pubsub.Event) error {
	evt := msg.Data.(pubsub.DatabaseEvent)
	c := models.RuntimeConfiguration{}
	// skip events that are not runtimeConfiguration changes
	if evt.Type != c.Type() {
		return nil
	}
	r.Log.Infow("deleting jobs from RuntimeConfiguration", "msg", msg)
	d, err := json.Marshal(evt.Object)
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
		"configuration-uuid": config.Uuid,
	}
	objs, err := r.Driver.GetAll(context.Background(), "jobs", job, conditions)
	if err != nil {
		return fmt.Errorf("could not get jobs: %w", err)
	}
	for _, o := range objs {
		obj := o.(*models.RuntimeConfigurationJob)
		err = r.Driver.Delete(context.Background(), job.Type(), obj.Uuid)
		if err != nil {
			return fmt.Errorf("could not delete job %v: %w", obj.Uuid, err)
		}
		event := runtime.RuntimeConfigurationJobPayload{
			Topic: fmt.Sprintf("runtime.configuration.%v", obj.RuntimeUuid),
			RuntimeConfigurationEvent: runtime.RuntimeConfigurationEvent{
				Data: nil,
				Type: runtime.PayloadEventDeleted,
				Uuid: obj.Uuid,
			},
		}
		pubsub.PublishPayload(event)
	}
	return err
}
