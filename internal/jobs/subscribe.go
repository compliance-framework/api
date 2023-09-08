package jobs

import (
	"sync"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type SubscribeJob struct {
	Log          *zap.SugaredLogger
	conn         *nats.Conn
	mu           *sync.Mutex
	runtimeJobCh chan<- any
}

func (s *SubscribeJob) Init() error {
	ch := make(chan<- any, 1)
	s.runtimeJobCh = ch
	if s.mu == nil {
		s.mu = &sync.Mutex{}
	}
	return nil
}

func (s *SubscribeJob) Connect(server string) error {
	err := s.Init()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil && s.runtimeJobCh != nil {
		return nil
	}

	nc, err := nats.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}
	s.conn = nc
	return nil
}

// Subscribe to a given topic
func (s *SubscribeJob) Subscribe(topic string) {
	s.conn.Subscribe(topic, func(msg *nats.Msg) {
		// on a new message received, forward to a given channel
		s.Log.Infow("Message received!", "msg", msg, "topic", topic)
	})
}
