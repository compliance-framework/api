package result

import (
	"fmt"

	"github.com/compliance-framework/configuration-service/event"
)

type Processor struct {
	// svc service.PlanService
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
		for msg := range ch {
			fmt.Printf("Received message: %v\n", msg)
		}
	}()
}
