package pubsub

import (
	"sync"

	"github.com/compliance-framework/configuration-service/internal/models/runtime"
)

type EventType int

const (
	ConfigurationUpdated EventType = iota
	ObjectCreated
	ObjectUpdated
	ManyObjectsCreated
	ManyObjectsDeleted
	ObjectDeleted
	RuntimeConfigurationJobEvent
)

type Event struct {
	Type EventType
	Data any
}

type DatabaseEvent struct {
	Type   string
	Object any
}

var (
	mu        sync.RWMutex
	subs      map[EventType][]chan Event
	closed    bool
	payloadCh []chan runtime.RuntimeConfigurationJobPayload
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

func SubscribePayload() <-chan runtime.RuntimeConfigurationJobPayload {
	mu.Lock()
	defer mu.Unlock()
	ch := make(chan runtime.RuntimeConfigurationJobPayload, 1)
	payloadCh = append(payloadCh, ch)
	return ch
}

func PublishPayload(data runtime.RuntimeConfigurationJobPayload) {
	mu.RLock()
	defer mu.RUnlock()
	for _, ch := range payloadCh {
		go func(ch chan runtime.RuntimeConfigurationJobPayload) {
			ch <- data
		}(ch)
	}
}

func Publish(topic EventType, data any) {
	mu.RLock()
	defer mu.RUnlock()

	if closed {
		return
	}

	event := Event{
		Type: topic,
		Data: data,
	}

	for _, ch := range subs[topic] {
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
