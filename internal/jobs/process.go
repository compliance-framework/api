package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	process "github.com/compliance-framework/configuration-service/internal/models/process"
	storeschema "github.com/compliance-framework/configuration-service/internal/stores/schema"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type EventProcessor struct {
	ch     chan *nats.Msg
	Log    *zap.SugaredLogger
	Driver storeschema.Driver
}

func (s *EventProcessor) Init(ch chan *nats.Msg) error {
	s.Log.Infow(">>INIT %s", ch)
	if s.Driver == nil {
		panic("EventProcessor driver is nil")
	}
	s.ch = ch
	return nil
}

func (s *EventProcessor) Run() {
	for msg := range s.ch {
		s.Log.Infow(">>RUN has Received message", "subject", msg.Subject, "data", string(msg.Data))
		a := process.JobResult{}
		err := json.Unmarshal(msg.Data, &a)
		if err != nil {
			s.Log.Errorf("failed to Unamrshal AssessmentResults: %w", err)
		}
		err = s.Save(a)
		if err != nil {
			s.Log.Errorf("failed to save AssessmentResults: %w", err)
		}
	}
}
func (s *EventProcessor) Save(res process.JobResult) error {
	s.Log.Infow(">>SaveAssessmentResult has Received message", "subject", res.AssessmentId)

	if s.Driver == nil {
		return fmt.Errorf("EventProcessor driver is nil")
	}

	// TODO: is the assessment id is even valid?

	uid, err := uuid.NewUUID()
	if err != nil {
		return fmt.Errorf("failed generating uid for assessesment result: %w", err)
	}
	res.Uuid = uid.String()
	err = s.Driver.Create(context.Background(), res.Type(), res.Uuid, res)
	if err != nil {
		return fmt.Errorf("failed to save assessment result: %w", err)
	}
	return nil

}
