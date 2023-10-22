package bus

import (
	"encoding/json"
	"github.com/compliance-framework/configuration-service/event"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
	"sync"
)

type chanHolder struct {
	Ch interface{}
}

var (
	conn  *nats.Conn
	subCh []chanHolder
	mu    sync.Mutex
	sugar *zap.SugaredLogger
)

func Listen(server string, l *zap.SugaredLogger) error {
	mu.Lock()
	defer mu.Unlock()

	if conn != nil && len(subCh) > 0 {
		return nil
	}

	sugar = l

	var err error
	conn, err = nats.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}
	subCh = make([]chanHolder, 0)
	return nil
}

func Subscribe[T any](topic event.TopicType) (chan T, error) {
	ch := make(chan T)
	_, err := conn.Subscribe(string(topic), func(m *nats.Msg) {
		var msg T
		err := json.Unmarshal(m.Data, &msg)
		if err != nil {
			sugar.Errorf("Error unmarshalling data: %v", err)
			return
		}
		ch <- msg
	})
	if err != nil {
		return nil, err
	}
	mu.Lock()
	subCh = append(subCh, chanHolder{Ch: ch})
	mu.Unlock()
	return ch, nil
}

func Publish(msg interface{}, topic event.TopicType) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.Publish(string(topic), data)
}

func Close() {
	conn.Close()
	for _, holder := range subCh {
		if ch, ok := holder.Ch.(chan any); ok {
			close(ch)
		}
	}
}
