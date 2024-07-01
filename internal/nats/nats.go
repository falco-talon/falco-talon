package nats

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	// "github.com/nats-io/nats.go"

	natsserver "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
)

type Client struct {
	nats.JetStreamContext
}

const (
	streamName     = "EVENTS"
	streamSubjects = "EVENTS.*"
)

type MessageWithContext struct {
	Ctx  context.Context
	Data []byte
}

var consumer, publisher *Client

func StartServer(timeWindow int) (*natsserver.Server, error) {
	ns, err := natsserver.NewServer(
		&natsserver.Options{
			JetStream: true,
			// StoreDir:  nats.MemoryStorage.String(),
		})
	if err != nil {
		return nil, err
	}
	go ns.Start()

	if !ns.ReadyForConnections(3 * time.Second) {
		return nil, fmt.Errorf("connection timeout")
	}

	consumer = new(Client)
	publisher = new(Client)

	if err := consumer.SetJetStreamContext(nats.DefaultURL); err != nil {
		return nil, err
	}
	if err := publisher.SetJetStreamContext(nats.DefaultURL); err != nil {
		return nil, err
	}

	if err := consumer.createStream(timeWindow); err != nil {
		return nil, err
	}

	return ns, nil
}

func (client *Client) SetJetStreamContext(addr string) error {
	nc, err := nats.Connect(addr)
	if err != nil {
		return err
	}

	jsc, err := nc.JetStream(nats.PublishAsyncMaxPending(256))
	if err != nil {
		return err
	}

	client.JetStreamContext = jsc
	return nil
}

func GetConsumer() *Client {
	return consumer
}

func GetPublisher() *Client {
	return publisher
}

func (client *Client) ConsumeMsg() (chan MessageWithContext, error) {
	c := make(chan MessageWithContext, 20)
	_, err := client.JetStreamContext.Subscribe(streamSubjects, func(m *nats.Msg) {
		propagator := otel.GetTextMapPropagator()
		ctx := propagator.Extract(context.Background(), propagation.HeaderCarrier(m.Header))

		if err := m.Ack(); err != nil {
			return
		}
		c <- MessageWithContext{Data: m.Data, Ctx: ctx}
	},
		nats.DeliverNew())

	if err != nil {
		return nil, err
	}

	return c, nil
}

func (client *Client) PublishMsg(ctx context.Context, id, msg string) error {
	natsMsg := &nats.Msg{
		Subject: streamName + "." + id,
		Data:    []byte(msg),
		Header:  nats.Header{},
	}

	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, propagation.HeaderCarrier(natsMsg.Header))

	if _, err := client.JetStreamContext.PublishMsg(natsMsg,
		nats.MsgId(id),
		nats.RetryAttempts(3),
		nats.RetryWait(500*time.Millisecond)); err != nil {
		return err
	}
	return nil
}

func (client *Client) createStream(timeWindow int) error {
	stream, err := client.JetStreamContext.StreamInfo(streamName)
	if err != nil {
		if err != nats.ErrStreamNotFound {
			return err
		}
	}
	if stream == nil {
		_, err = client.JetStreamContext.AddStream(&nats.StreamConfig{
			Name:              streamName,
			Subjects:          []string{streamSubjects},
			Duplicates:        time.Duration(timeWindow) * time.Second,
			MaxAge:            time.Duration(timeWindow) * time.Second,
			MaxMsgsPerSubject: 1,
			Storage:           nats.MemoryStorage,
		})
		if err != nil {
			return err
		}
	}
	return nil
}
