package jobs

import (
	"sync"

	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type EventSubscriber struct {
	Log           *zap.SugaredLogger
	driver        *internal
	conn          *nats.Conn
	mu            *sync.Mutex
	subscriptions map[string]*Subscription
}

type Subscription struct {
	sub *nats.Subscription
	ch  chan *nats.Msg
}

func (s *EventSubscriber) Init() error {
	if s.driver == nil {
		s.driver = &internal{
			ConnectFn:    DefaultConnect,
			NewEncodedFn: DefaultEncodedConn,
		}
	}
	if s.mu == nil {
		s.mu = &sync.Mutex{}
	}
	s.subscriptions = make(map[string]*Subscription)
	return nil
}

func (s *EventSubscriber) Connect(server string) error {
	err := s.Init()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn != nil {
		return nil
	}

	nc, err := s.driver.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}

	s.conn = nc
	return nil
}

func (s *EventSubscriber) createSubscription(topic string) *Subscription {
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.subscriptions[topic]
	if !ok {
		ch := make(chan *nats.Msg, 1)
		sub = &Subscription{
			ch: ch,
		}
		s.subscriptions[topic] = sub
	}
	return sub
}

// Subscribe to a given topic in a channel
func (s *EventSubscriber) Subscribe(topic string) chan *nats.Msg {
	sub := s.createSubscription(topic)
	subscription, err := s.conn.ChanSubscribe(topic, sub.ch)
	if err != nil {
		s.Log.Errorw("Error subscribing to topic", "topic", topic, "error", err)
		return nil
	}
	sub.sub = subscription
	s.Log.Infow("Subscribed to topic", "topic", topic)
	return sub.ch
}

func (s *EventSubscriber) Close() error {
	for k := range s.subscriptions {
		err := s.CloseSubscription(k)
		if err != nil {
			return err
		}
	}
	s.conn.Close()
	return nil
}

func (s *EventSubscriber) CloseSubscription(topic string) error {
	sub, ok := s.subscriptions[topic]
	if !ok {
		return nil
	}
	err := sub.sub.Unsubscribe()
	if err != nil {
		return err
	}
	close(sub.ch)
	s.subscriptions[topic] = nil
	delete(s.subscriptions, topic)
	return nil
}
