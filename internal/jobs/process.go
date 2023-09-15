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

type ProcessJob struct {
	ch     chan *nats.Msg
	Log    *zap.SugaredLogger
	Driver storeschema.Driver
}

func (s *ProcessJob) Init(ch chan *nats.Msg) error {
	s.Log.Infow(">>INIT %s", ch)
	if s.Driver == nil {
		panic("ProcessJob driver is nil")
	}
	s.ch = ch
	return nil
}

func (s *ProcessJob) Run() {
	for msg := range s.ch {
		s.Log.Infow(">>RUN has Received message", "subject", msg.Subject, "data", string(msg.Data))
		a := process.AssessmentResults{}
		json.Unmarshal(msg.Data, &a)
		s.SaveAssessmentResults(a)
	}
}
func (s *ProcessJob) SaveAssessmentResults(assessmentResults process.AssessmentResults) error {
	s.Log.Infow(">>SaveAssessmentResults has Received message", "subject", assessmentResults.AssessmentId, "data", assessmentResults.Outputs)

	if s.Driver == nil {
		return fmt.Errorf("ProcessJob driver is nil")
	}

	// TODO: is the assessment id is even valid?

	uid, err := uuid.NewUUID()
	if err != nil {
		return fmt.Errorf("failed generating uid for assessesment result: %w", err)
	}
	assessmentResults.Id = uid.String()
	err = s.Driver.Create(context.Background(), "AssessmentResults", assessmentResults.Id, assessmentResults)
	if err != nil {
		return fmt.Errorf("failed to save assessment result: %w", err)
	}
	return nil

}
