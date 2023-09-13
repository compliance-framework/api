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
	job := &models.RuntimeConfigurationJob{}
	err = r._makeJob(c, job)
	if err != nil {
		return fmt.Errorf("could not prepare job spec for %v: %w", c.Uuid, err)
	}
	err = r._createJob(job)
	if err != nil {
		return fmt.Errorf("could not create job %v: %w", job.Uuid, err)
	}
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
	if configJob.RuntimeUuid != c.RuntimeUuid {
		err = r._deleteJob(configJob)
		if err != nil {
			return fmt.Errorf("could not update job %v: %w", configJob.Uuid, err)
		}
		job := &models.RuntimeConfigurationJob{}
		err = r._makeJob(c, job)
		if err != nil {
			return fmt.Errorf("could not prepare job spec for %v: %w", c.Uuid, err)
		}
		err = r._createJob(job)
		if err != nil {
			return fmt.Errorf("could not update job %v: %w", configJob.Uuid, err)
		}
	} else {
		err = r._makeJob(c, configJob)
		if err != nil {
			return fmt.Errorf("could not prepare job spec for %v: %w", c.Uuid, err)
		}
		err = r._updateJob(configJob)
		if err != nil {
			return fmt.Errorf("could not update job for config %v: %w", c.Uuid, err)
		}
	}
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

func (r *RuntimeJobCreator) _getPlugin(uuid string) (*models.RuntimePlugin, error) {
	plugin := &models.RuntimePlugin{}
	err := r.Driver.Get(context.Background(), plugin.Type(), uuid, plugin)
	if err != nil {
		return nil, fmt.Errorf("could not get plugin %v: %w", uuid, err)
	}
	return plugin, nil
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

func (r *RuntimeJobCreator) _getActivity(c *models.RuntimeConfiguration) (*oscal.CommonActivity, error) {
	ap, err := r._getAp(c.AssessmentPlanUuid)
	if err != nil {
		return nil, fmt.Errorf("could not get assessment-plan %v: %w", c.AssessmentPlanUuid, err)
	}
	if ap.LocalDefinitions == nil || ap.LocalDefinitions.Activities == nil {
		return nil, fmt.Errorf("no activities defined on assessment-plan %v", c.AssessmentPlanUuid)
	}
	ans := &oscal.CommonActivity{}
	for _, a := range ap.LocalDefinitions.Activities {
		if c.ActivityUuid == a.Uuid {
			ans = a
		}
	}
	if ans.Uuid == "" {
		return nil, fmt.Errorf("Could not find activity %v on assessment-plan %v", c.ActivityUuid, c.AssessmentPlanUuid)
	}
	return ans, nil
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
	publish(obj.Uuid, obj.RuntimeUuid, runtime.PayloadEventDeleted, nil)
	return nil
}

func (r *RuntimeJobCreator) _createJob(o interface{}) error {
	obj := o.(*models.RuntimeConfigurationJob)
	err := r.Driver.Create(context.Background(), obj.Type(), obj.Uuid, obj)
	if err != nil {
		return fmt.Errorf("could not create job %v: %w", obj.Uuid, err)
	}
	publish(obj.Uuid, obj.RuntimeUuid, runtime.PayloadEventCreated, obj)
	return nil
}

func (r *RuntimeJobCreator) _updateJob(o interface{}) error {
	obj := o.(*models.RuntimeConfigurationJob)
	err := r.Driver.Update(context.Background(), obj.Type(), obj.Uuid, obj)
	if err != nil {
		return fmt.Errorf("could not update job %v: %w", obj.Uuid, err)
	}
	publish(obj.Uuid, obj.RuntimeUuid, runtime.PayloadEventUpdated, obj)
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

func (r *RuntimeJobCreator) _makeJob(c *models.RuntimeConfiguration, job *models.RuntimeConfigurationJob) error {
	activity, err := r._getActivity(c)
	if err != nil {
		return fmt.Errorf("could not get activity %v for configuration %v: %w", c.ActivityUuid, c.Uuid, err)
	}
	props := assembleProperties(&oscal.Task{}, activity)
	plugin, err := r._getPlugin(c.PluginUuid)
	if err != nil {
		return fmt.Errorf("could not get plugins for configuration %v: %w", c.Uuid, err)
	}
	job.Uuid = c.Uuid
	job.Selector = c.Selector
	job.RuntimeUuid = c.RuntimeUuid
	job.AssessmentUuid = c.AssessmentPlanUuid
	job.Schedule = c.Schedule
	job.ActivityUuid = c.ActivityUuid
	job.Plugin = plugin
	job.Parameters = props
	return nil
}
