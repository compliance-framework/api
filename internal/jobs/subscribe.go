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
	RuntimeJobCh chan *nats.Msg
}

func (s *SubscribeJob) Init() error {
	ch := make(chan *nats.Msg, 1)
	s.RuntimeJobCh = ch
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

	if s.conn != nil && s.RuntimeJobCh != nil {
		return nil
	}

	nc, err := nats.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}
	s.conn = nc
	return nil
}

// Subscribe to a given topic in a channel
func (s *SubscribeJob) Subscribe(topic string) {
	s.conn.ChanSubscribe(topic, s.RuntimeJobCh)
	s.Log.Infow("Subscribed to topic", "topic", topic)

}

func (s *SubscribeJob) ReadFromChannel() {
	for msg := range s.RuntimeJobCh {
		s.Log.Infow("Message received!", "msg", msg)
	}
}
