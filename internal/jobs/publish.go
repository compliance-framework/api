package jobs

import (
	"encoding/json"
	"sync"

	"github.com/compliance-framework/configuration-service/internal/pubsub"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

type PublishJob struct {
	conn         *nats.Conn
	mu           *sync.Mutex
	runtimeJobCh <-chan pubsub.Event
	Log          *zap.SugaredLogger
}

func (p *PublishJob) Init() error {
	ch, err := pubsub.Subscribe(pubsub.RuntimeConfigurationJobEvent)
	p.runtimeJobCh = ch
	if err != nil {
		return err
	}
	if p.mu == nil {
		p.mu = &sync.Mutex{}
	}
	return nil
}

func (p *PublishJob) Connect(server string) error {
	err := p.Init()
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.conn != nil && p.runtimeJobCh != nil {
		return nil
	}

	c, err := nats.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}
	p.conn = c
	return nil
}

func (p *PublishJob) Run() {
	for msg := range p.runtimeJobCh {
		d, err := json.Marshal(msg.Data)
		if err != nil {
			p.Log.Errorw("could not marshal message", "msg", msg, "err", err.Error())
			continue
		}
		subj := "runtime/job-update"
		err = p.Publish(subj, d)
		if err != nil {
			p.Log.Errorw("could not publish message", "msg", msg, "err", err.Error())
		}
	}
}
func (p *PublishJob) Publish(subj string, data []byte) error {
	return p.conn.Publish(subj, data)
}
