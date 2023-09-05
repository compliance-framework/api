package jobs

import (
	"sync"

	"github.com/compliance-framework/configuration-service/internal/models/runtime"
	"github.com/compliance-framework/configuration-service/internal/pubsub"
	"github.com/nats-io/nats.go"
)

type NatsIfc interface {
	Connect(url string, options ...nats.Option) (*nats.Conn, error)
	NewEncodedConn(c *nats.Conn, enc nats.Encoder) (EncoderIfc, error)
}

type EncoderIfc interface {
	BindSendChan(subject string, channel any) error
}
type internal struct {
	ConnectFn    func(url string, options ...nats.Option) (*nats.Conn, error)
	NewEncodedFn func(c *nats.Conn, enc string) (EncoderIfc, error)
}

func (i *internal) Connect(url string, options ...nats.Option) (*nats.Conn, error) {
	return i.ConnectFn(url, options...)
}

func (i *internal) NewEncodedConn(c *nats.Conn, enc string) (EncoderIfc, error) {
	return i.NewEncodedFn(c, enc)
}

func DefaultConnect(url string, options ...nats.Option) (*nats.Conn, error) {
	return nats.Connect(url, options...)
}

func DefaultEncodedConn(c *nats.Conn, enc string) (EncoderIfc, error) {
	return nats.NewEncodedConn(c, enc)
}

type encoder struct {
	BindSendFn func(subject string, channel any) error
}

func (e *encoder) BindSendChan(subject string, channel any) error {
	return e.BindSendFn(subject, channel)
}

type PublishJob struct {
	conn         *nats.Conn
	mu           *sync.Mutex
	runtimeJobCh <-chan runtime.RuntimeConfigurationJob
	driver       *internal
}

func (p *PublishJob) Init() error {
	if p.driver == nil {
		p.driver = &internal{
			ConnectFn:    DefaultConnect,
			NewEncodedFn: DefaultEncodedConn,
		}
	}
	ch := pubsub.SubscribePayload()
	p.runtimeJobCh = ch
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

	c, err := p.driver.Connect(server, nats.ReconnectBufSize(5*1024*1024))
	if err != nil {
		return err
	}
	p.conn = c
	ec, err := p.driver.NewEncodedConn(p.conn, nats.JSON_ENCODER)
	if err != nil {
		return err
	}
	err = ec.BindSendChan("runtime/job-update", p.runtimeJobCh)
	if err != nil {
		return err
	}
	return nil
}
