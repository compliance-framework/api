package runtime

import (
	"fmt"
	"time"

	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	"github.com/compliance-framework/configuration-service/service"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Processor struct {
	svc *service.PlanService
	sub event.Subscriber[ExecutionResult]
}

func NewProcessor(s event.Subscriber[ExecutionResult], svc *service.PlanService) *Processor {
	return &Processor{
		sub: s,
		svc: svc,
	}
}

func (r *Processor) Listen() {
	ch, err := r.sub(event.TopicTypeResult)
	if err != nil {
		panic(err)
	}

	go func() {
		for msg := range ch {
			fmt.Printf("Received message: %v\n", msg)

			// TODO: Create an actor for the runtime that publishes the events to store it as the origin
			// TODO: Handle execution status

			subject := domain.Subject{
				Id:          primitive.NewObjectID(),
				SubjectId:   msg.Subject.Id,
				Type:        msg.Subject.Type,
				Title:       msg.Subject.Title,
				Description: msg.Subject.Description,
				Props:       msg.Subject.Props,
				Links:       msg.Subject.Links,
				Remarks:     msg.Subject.Remarks,
			}

			err := r.svc.SaveSubject(subject)
			if err != nil {
				return
			}

			observations := make([]domain.Observation, len(msg.Observations))
			for i, o := range msg.Observations {
				evidences := make([]domain.Evidence, len(o.RelevantEvidence))
				for j, e := range o.RelevantEvidence {
					evidences[j] = domain.Evidence{
						Id:          primitive.NewObjectID(),
						Title:       e.Title,
						Description: e.Description,
						Props:       e.Props,
						Links:       e.Links,
						Remarks:     e.Remarks,
					}
				}

				observations[i] = domain.Observation{
					Id:               primitive.NewObjectID(),
					Title:            o.Title,
					Description:      o.Description,
					Props:            o.Props,
					Links:            o.Links,
					Remarks:          o.Remarks,
					Subjects:         []primitive.ObjectID{subject.Id},
					Collected:        o.Collected,
					Expires:          o.Expires,
					RelevantEvidence: evidences,
				}
			}

			risks := make([]domain.Risk, len(msg.Risks))
			for i, r := range msg.Risks {
				risks[i] = domain.Risk{
					Id:          primitive.NewObjectID(),
					Title:       r.Title,
					Description: r.Description,
					Statement:   r.Statement,
					Props:       r.Props,
					Links:       r.Links,
					RelatedObservations: []primitive.ObjectID{
						observations[0].Id,
					},
				}
			}

			findings := make([]domain.Finding, len(msg.Findings))
			for i, f := range msg.Findings {
				findings[i] = domain.Finding{
					Id:          primitive.NewObjectID(),
					Title:       f.Title,
					Description: f.Description,
					Props:       f.Props,
					Links:       f.Links,
					Remarks:     f.Remarks,
					TargetId:    subject.Id,
				}
			}

			// TODO: Start and End times should arrive from the runtime inside the message
			logs := make([]domain.LogEntry, len(msg.Logs))
			for i, l := range msg.Logs {
				logs[i] = domain.LogEntry{
					Title:       l.Title,
					Description: l.Description,
					Props:       l.Props,
					Links:       l.Links,
					Remarks:     l.Remarks,
					Start:       time.Now(),
					End:         time.Now(),
				}
			}

			// TODO: Start and End times should arrive from the runtime inside the message
			result := domain.Result{
				Id:            primitive.NewObjectID(),
				Observations:  observations,
				Risks:         risks,
				Findings:      findings,
				AssessmentLog: logs,
				Start:         time.Now(),
				End:           time.Now(),
			}

			err = r.svc.SaveResult(msg.AssessmentId, result)
			if err != nil {
				return
			}
		}
	}()
}
