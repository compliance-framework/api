package jobs

import (
	"sync"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type SubscribeJob struct {
	Log           *zap.SugaredLogger
	conn          *nats.Conn
	mu            *sync.Mutex
	subscriptions map[string]chan *nats.Msg
}

func (s *SubscribeJob) Init() error {
	if s.mu == nil {
		s.mu = &sync.Mutex{}
	}
	s.subscriptions = make(map[string]chan *nats.Msg)
	return nil
}

func (s *SubscribeJob) Connect(server string) error {
	err := s.Init()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		return nil
	}

	nc, err := nats.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}

	s.conn = nc
	return nil
}

func (s *SubscribeJob) createChannel(topic string) chan *nats.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.subscriptions[topic]
	if !ok {
		ch = make(chan *nats.Msg, 1)
		s.subscriptions[topic] = ch
	}
	return ch
}

// Subscribe to a given topic in a channel
func (s *SubscribeJob) Subscribe(topic string) {
	ch := s.createChannel(topic)
	s.conn.ChanSubscribe(topic, ch)
	s.Log.Infow("Subscribed to topic", "topic", topic)
}

func (s *SubscribeJob) ReadFromChannel(topic string) {
	ch, ok := s.subscriptions[topic]
	if !ok {
		s.Log.Errorw("Channel not found", "topic", topic)
		return
	}
	for msg := range ch {
		s.Log.Infow("Message received!", "msg", msg)
	}
}
