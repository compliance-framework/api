package runtime

import (
	"fmt"
	"github.com/compliance-framework/configuration-service/event"
	"github.com/compliance-framework/configuration-service/service"
)

type Processor struct {
	svc service.PlanService
	sub event.Subscriber[event.ResultEvent]
}

func NewProcessor(s event.Subscriber[event.ResultEvent]) *Processor {
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
			}
		}
	}()
}
