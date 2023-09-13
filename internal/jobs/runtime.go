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
	c := &models.RuntimeConfiguration{}
	if evt.Type != c.Type() {
		return nil
	}
	// skip events that are not runtimeConfiguration changes
	r.Log.Infow("deleting jobs from RuntimeConfiguration", "msg", msg)
	err := loadConfig(evt, c)
	if err != nil {
		return fmt.Errorf("could not get RuntimeConfiguration: %w", err)
	}
	task, err := r._getTask(c)
	if err != nil {
		return fmt.Errorf("could not get task %v: %w", c.TaskUuid, err)
	}
	activities, err := r._getActivities(c, task)
	if err != nil {
		return fmt.Errorf("could not get activities for task %v: %w", c.TaskUuid, err)
	}
	processed := make([]*models.Activity, 0)
	for _, a := range activities {
		props := assembleProperties(task, a)
		// TODO if Activities have specific parameter configuring a specific plugin, use that instead
		plugins, err := r._getPlugins(c.PluginUuids)
		if err != nil {
			return fmt.Errorf("could not get plugins for configuration %v: %w", c.Uuid, err)
		}
		// TODO if Activities have a specific selector, use that instead
		activity := &models.Activity{
			Id:         a.Uuid,
			Selector:   c.Selector,
			Parameters: props,
			ControlId:  "",
			Plugins:    plugins,
		}
		processed = append(processed, activity)
	}
	if err != nil {
		return fmt.Errorf("could not generate uuid: %w", err)
	}
	job := &models.RuntimeConfigurationJob{
		Uuid:              c.Uuid,
		ConfigurationUuid: c.Uuid,
		RuntimeUuid:       c.RuntimeUuid,
		SspId:             "",
		AssessmentId:      c.AssessmentPlanUuid,
		TaskId:            c.TaskUuid,
		Schedule:          c.Schedule,
		Activities:        processed,
	}
	err = r.Driver.Create(context.Background(), job.Type(), job.Uuid, job)
	if err != nil {
		return fmt.Errorf("could not create job %v: %w", job.Uuid, err)
	}
	publish(job.Uuid, job.RuntimeUuid, runtime.PayloadEventCreated, job)
	return nil
}

func (r *RuntimeJobCreator) updateJobs(msg pubsub.Event) error {
	evt := msg.Data.(pubsub.DatabaseEvent)
	c := &models.RuntimeConfiguration{}
	if evt.Type != c.Type() {
		return nil
	}
	// skip events that are not runtimeConfiguration changes
	r.Log.Infow("deleting jobs from RuntimeConfiguration", "msg", msg)
	err := loadConfig(evt, c)
	if err != nil {
		return fmt.Errorf("could not get RuntimeConfiguration: %w", err)
	}
	configJob, err := r._getJob(c.Uuid)
	if err != nil {
		return fmt.Errorf("could not get jobs for configuration %v: %w", c.Uuid, err)
	}
	task, err := r._getTask(c)
	if err != nil {
		return fmt.Errorf("could not get task %v: %w", c.TaskUuid, err)
	}
	activities, err := r._getActivities(c, task)
	if err != nil {
		return fmt.Errorf("could not get activities for task %v: %w", c.TaskUuid, err)
	}
	processed := make([]*models.Activity, 0)
	for _, a := range activities {
		props := assembleProperties(task, a)
		// TODO if Activities have specific parameter configuring a specific plugin, use that instead
		plugins, err := r._getPlugins(c.PluginUuids)
		if err != nil {
			return fmt.Errorf("could not get plugins for configuration %v: %w", c.Uuid, err)
		}
		// TODO if Activities have a specific selector, use that instead
		activity := &models.Activity{
			Id:         a.Uuid,
			Selector:   c.Selector,
			Parameters: props,
			ControlId:  "",
			Plugins:    plugins,
		}
		processed = append(processed, activity)
	}
	configJob.RuntimeUuid = c.RuntimeUuid
	configJob.SspId = ""
	configJob.AssessmentId = c.AssessmentPlanUuid
	configJob.TaskId = c.TaskUuid
	configJob.Schedule = c.Schedule
	configJob.Activities = processed
	err = r.Driver.Update(context.Background(), configJob.Type(), configJob.Uuid, configJob)
	if err != nil {
		return fmt.Errorf("could not update job %v: %w", configJob.Uuid, err)
	}
	publish(configJob.Uuid, configJob.RuntimeUuid, runtime.PayloadEventUpdated, configJob)
	return nil
}

func (r *RuntimeJobCreator) deleteJobs(msg pubsub.Event) error {
	evt := msg.Data.(pubsub.DatabaseEvent)
	c := &models.RuntimeConfiguration{}
	if evt.Type != c.Type() {
		return nil
	}
	// skip events that are not runtimeConfiguration changes
	r.Log.Infow("deleting jobs from RuntimeConfiguration", "msg", msg)
	err := loadConfig(evt, c)
	if err != nil {
		return fmt.Errorf("could not get RuntimeConfiguration: %w", err)
	}
	job, err := r._getJob(c.Uuid)
	if err != nil {
		return fmt.Errorf("could not get jobs: %w", err)
	}
	err = r._deleteJob(job)
	if err != nil {
		return fmt.Errorf("could not delete job %v: %w", job, err)
	}
	return nil
}

func (r *RuntimeJobCreator) _getPlugins(uuids []string) ([]*models.RuntimePlugin, error) {
	ans := make([]*models.RuntimePlugin, 0)
	for _, uuid := range uuids {
		plugin := &models.RuntimePlugin{}
		err := r.Driver.Get(context.Background(), plugin.Type(), uuid, plugin)
		if err != nil {
			return nil, fmt.Errorf("could not get plugin %v: %w", uuid, err)
		}
		ans = append(ans, plugin)
	}
	return ans, nil
}

func assembleProperties(task *oscal.Task, activity *oscal.CommonActivity) []*models.RuntimeParameters {
	ans := make([]*models.RuntimeParameters, 0)
	for _, p := range task.Props {
		param := &models.RuntimeParameters{
			Name:  p.Name,
			Value: p.Value,
		}
		ans = append(ans, param)
	}
	for _, p := range activity.Props {
		param := &models.RuntimeParameters{
			Name:  p.Name,
			Value: p.Value,
		}
		ans = append(ans, param)
	}
	return ans

}

func (r *RuntimeJobCreator) _getActivities(c *models.RuntimeConfiguration, task *oscal.Task) ([]*oscal.CommonActivity, error) {
	ap, err := r._getAp(c.AssessmentPlanUuid)
	if err != nil {
		return nil, fmt.Errorf("could not get assessment-plan %v: %w", c.AssessmentPlanUuid, err)
	}
	if ap.LocalDefinitions == nil || ap.LocalDefinitions.Activities == nil {
		return nil, fmt.Errorf("no activities defined on assessment-plan %v", c.AssessmentPlanUuid)
	}
	ans := make([]*oscal.CommonActivity, 0)
	for _, t := range task.AssociatedActivities {
		for _, a := range ap.LocalDefinitions.Activities {
			if t.ActivityUuid == a.Uuid {
				ans = append(ans, a)
			}
		}
	}
	// TODO we could change this logic to provide more context (which uuids failed?)
	if len(ans) != len(task.AssociatedActivities) {
		return nil, fmt.Errorf("some activities of task %v could not be found in assessment-plan %v", c.TaskUuid, c.AssessmentPlanUuid)
	}
	return ans, nil
}

func (r *RuntimeJobCreator) _getTask(c *models.RuntimeConfiguration) (*oscal.Task, error) {
	ap, err := r._getAp(c.AssessmentPlanUuid)
	if err != nil {
		return nil, fmt.Errorf("could not get assessment-plan %v: %w", c.AssessmentPlanUuid, err)
	}
	found := false
	task := &oscal.Task{}
	for i, t := range ap.Tasks {
		if t.Uuid == c.TaskUuid {
			task = ap.Tasks[i]
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("task %v not found on assessment-plan %v", c.TaskUuid, c.AssessmentPlanUuid)
	}
	return task, nil
}

func (r *RuntimeJobCreator) _getAp(uuid string) (*oscal.AssessmentPlan, error) {
	ap := &oscal.AssessmentPlan{}
	err := r.Driver.Get(context.Background(), ap.Type(), uuid, ap)
	if err != nil {
		return nil, fmt.Errorf("could not get assessment-plan %v: %w", uuid, err)
	}
	return ap, nil
}

func loadConfig(evt pubsub.DatabaseEvent, config *models.RuntimeConfiguration) error {
	d, err := json.Marshal(evt.Object)
	if err != nil {
		return fmt.Errorf("could not marshal data: %w", err)
	}
	err = config.FromJSON(d)
	if err != nil {
		return fmt.Errorf("could not load data: %w", err)
	}
	return nil
}

func (r *RuntimeJobCreator) _getJob(uuid string) (*models.RuntimeConfigurationJob, error) {
	job := &models.RuntimeConfigurationJob{}
	err := r.Driver.Get(context.Background(), job.Type(), uuid, job)
	return job, err
}

func (r *RuntimeJobCreator) _deleteJob(o interface{}) error {
	job := &models.RuntimeConfigurationJob{}
	obj := o.(*models.RuntimeConfigurationJob)
	err := r.Driver.Delete(context.Background(), job.Type(), obj.Uuid)
	if err != nil {
		return fmt.Errorf("could not delete job %v: %w", obj.Uuid, err)
	}
	publish(obj.Uuid, obj.RuntimeUuid, runtime.PayloadEventDeleted, obj)
	return nil
}

func publish(objUuid, runtimeUuid string, payload runtime.PayloadEventType, data *models.RuntimeConfigurationJob) {
	event := runtime.RuntimeConfigurationJobPayload{
		Topic: fmt.Sprintf("runtime.configuration.%v", runtimeUuid),
		RuntimeConfigurationEvent: runtime.RuntimeConfigurationEvent{
			Data: data,
			Type: payload,
			Uuid: objUuid,
		},
	}
	pubsub.PublishPayload(event)

}
