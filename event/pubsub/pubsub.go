package pubsub

import (
	"sync"
)

type EventType int

const (
	ConfigurationUpdated EventType = iota
)

type Event struct {
	Type EventType
	Data any
}

var (
	mu     sync.RWMutex
	subs   map[EventType][]chan Event
	closed bool
)

func init() {
	subs = make(map[EventType][]chan Event)
	closed = false
}

func Subscribe(topic EventType) (<-chan Event, error) {
	mu.Lock()
	defer mu.Unlock()

	ch := make(chan Event, 1)
	subs[topic] = append(subs[topic], ch)
	return ch, nil
}

func Publish(event Event) {
	mu.RLock()
	defer mu.RUnlock()

	if closed {
		return
	}

	for _, ch := range subs[event.Type] {
		go func(ch chan Event) {
			ch <- event
		}(ch)
	}
}

func Close() {
	mu.Lock()
	defer mu.Unlock()

	if !closed {
		closed = true
		for _, subs := range subs {
			for _, ch := range subs {
				close(ch)
			}
		}
	}
}
