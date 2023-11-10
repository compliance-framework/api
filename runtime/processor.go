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

				// TODO: This should happen inside the domain package
				result := domain.Result{
					Id: primitive.NewObjectID(),
				}
				err := r.svc.AddResult(msg.AssessmentId, result)
				if err != nil {
					return
				}
			}
		}
	}()
}
