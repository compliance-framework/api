package jobs

import (
	"context"
	"encoding/json"
	"fmt"

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
	s.ch = ch
	return nil
}

func (s *ProcessJob) Run() {
	for msg := range s.ch {
		s.Log.Infow(">>RUN has Received message", "subject", msg.Subject, "data", string(msg.Data))
		a := AssessmentResults{}
		json.Unmarshal(msg.Data, &a)
		s.SaveAssessmentResults(a)
	}
}

type ResultData struct {
	Message string `json:"message"`
}
type Output struct {
	ResultData ResultData `json:"ResultData"`
}

type AssessmentResults struct {
	Id           string
	AssessmentId string            `json:"AssessmentId"`
	Outputs      map[string]Output `json:"Outputs"`
}

func (s *ProcessJob) SaveAssessmentResults(AssessmentResults AssessmentResults) error {
	s.Log.Infow(">>RUN has Received message", "subject", AssessmentResults.AssessmentId, "data", AssessmentResults.Outputs)

	// TODO: is the assessment id is even valid?

	uid, err := uuid.NewUUID()
	if err != nil {
		return fmt.Errorf("failed generating uid for assessesment result: %w", err)
	}
	AssessmentResults.Id = uid.String()
	err = s.Driver.Create(context.Background(), "AssessmentResults", AssessmentResults.Id, AssessmentResults)
	if err != nil {
		return fmt.Errorf("failed to save assessment result: %w", err)
	}
	return nil

}
