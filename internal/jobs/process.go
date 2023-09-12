package jobs

import (
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type ProcessJob struct {
	ch  chan *nats.Msg
	Log *zap.SugaredLogger
}

func (s *ProcessJob) Init(ch chan *nats.Msg) error {
	s.ch = ch
	return nil
}

func (s *ProcessJob) Run() {
	for msg := range s.ch {
		s.Log.Infow(">>RUN has Received message", "subject", msg.Subject, "data", string(msg.Data))
	}
}

//
/* DONE: NATS MSG >> Subscribe.go >> Golang Channel >> Process.go
   TODO: Process.go >> Save Assessment Results on DB
*/
