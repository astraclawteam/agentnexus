package tasks

import (
	"context"
	"encoding/json"

	"github.com/nats-io/nats.go"
)

type NATSPublisher struct {
	js nats.JetStreamContext
}

func NewNATSPublisher(conn *nats.Conn) (*NATSPublisher, error) {
	js, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	return &NATSPublisher{js: js}, nil
}

func (p *NATSPublisher) PublishTaskEvent(ctx context.Context, event TaskEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = p.js.Publish(event.Subject, payload, nats.Context(ctx))
	return err
}
