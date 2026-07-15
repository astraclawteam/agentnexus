package actions

import (
	"context"
	"encoding/json"

	"github.com/nats-io/nats.go"
)

// SubjectActionDispatch is the JetStream subject the transactional outbox
// publishes durable dispatch intents on (gateway -> connector host).
const SubjectActionDispatch = "agentnexus.actions.dispatch"

// NATSPublisher delivers durable dispatch intents to the connector host over
// NATS JetStream. It is the concrete Publisher wired in production; the outbox
// row is committed BEFORE this publishes, so a publish failure only leaves the
// intent pending for the recovery pump — it never creates a second side effect.
type NATSPublisher struct {
	js      nats.JetStreamContext
	subject string
}

// NewNATSPublisher builds a JetStream-backed dispatch publisher.
func NewNATSPublisher(conn *nats.Conn) (*NATSPublisher, error) {
	js, err := conn.JetStream()
	if err != nil {
		return nil, err
	}
	return &NATSPublisher{js: js, subject: SubjectActionDispatch}, nil
}

// PublishDispatch publishes one durable dispatch intent to JetStream.
func (p *NATSPublisher) PublishDispatch(ctx context.Context, message DispatchMessage) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	_, err = p.js.Publish(p.subject, payload, nats.Context(ctx))
	return err
}
