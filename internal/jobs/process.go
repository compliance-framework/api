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
		a := process.AssessmentResult{}
		json.Unmarshal(msg.Data, &a)
		s.SaveAssessmentResult(a)
	}
}
func (s *ProcessJob) SaveAssessmentResult(assessmentResult process.AssessmentResult) error {
	s.Log.Infow(">>SaveAssessmentResult has Received message", "subject", assessmentResult.AssessmentId, "data", assessmentResult.Outputs)

	if s.Driver == nil {
		return fmt.Errorf("ProcessJob driver is nil")
	}

	// TODO: is the assessment id is even valid?

	uid, err := uuid.NewUUID()
	if err != nil {
		return fmt.Errorf("failed generating uid for assessesment result: %w", err)
	}
	assessmentResult.Id = uid.String()
	err = s.Driver.Create(context.Background(), assessmentResult.Type(), assessmentResult.Id, assessmentResult)
	if err != nil {
		return fmt.Errorf("failed to save assessment result: %w", err)
	}
	return nil

}
