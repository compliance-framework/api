package jobs

import (
	"github.com/compliance-framework/configuration-service/internal/pubsub"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
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

func (r *RuntimeJobCreator) createJobs(msg pubsub.Event) error {
	r.Log.Infow("creating jobs from RuntimeConfiguration", "msg", msg)
	return nil
}

func (r *RuntimeJobCreator) updateJobs(msg pubsub.Event) error {
	r.Log.Infow("updating jobs from RuntimeConfiguration", "msg", msg)
	return nil
}

func (r *RuntimeJobCreator) deleteJobs(msg pubsub.Event) error {
	r.Log.Infow("deleting jobs from RuntimeConfiguration", "msg", msg)
	return nil
}
