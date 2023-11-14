package runtime

import (
	"fmt"
	"github.com/compliance-framework/configuration-service/domain"
	"github.com/compliance-framework/configuration-service/event"
	"github.com/compliance-framework/configuration-service/service"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Processor struct {
	svc service.PlanService
	sub event.Subscriber[ResultEvent]
}

func NewProcessor(s event.Subscriber[ResultEvent]) *Processor {
	return &Processor{
		sub: s,
	}
}

func (r *Processor) Listen() {
	ch, err := r.sub(event.TopicTypeResult)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case msg := <-ch:
				fmt.Printf("Received message: %v\n", msg)

				observations := make([]domain.Observation, len(msg.Results.Observations))
				for i, o := range msg.Results.Observations {
					observations[i] = domain.Observation{
						Id:          primitive.NewObjectID(),
						Collected:   o.Collected,
						Title:       o.Title,
						Description: o.Description,
						Expires:     o.Expires,
						Remarks:     o.Remarks,
					}
				}

				risks := make([]domain.Risk, len(msg.Results.Risks))
				for i, r := range msg.Results.Risks {
					risks[i] = domain.Risk{
						Id:          primitive.NewObjectID(),
						Description: r.Description,
					}
				}

				// TODO: This should happen inside the domain package
				result := domain.Result{
					Id:           primitive.NewObjectID(),
					Observations: observations,
					Risks:        risks,
				}
				err := r.svc.AddResult(msg.AssessmentId, result)
				if err != nil {
					return
				}
			}
		}
	}()
}
