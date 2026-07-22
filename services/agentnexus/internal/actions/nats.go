package actions

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nats-io/nats.go"
)

// SubjectActionDispatch is the JetStream subject the transactional outbox
// publishes durable dispatch intents on (gateway -> connector host).
const SubjectActionDispatch = "agentnexus.actions.dispatch"

// NATSPublisher delivers durable dispatch intents to the connector host over
// NATS JetStream. It is the concrete Publisher wired in production; the outbox
// row is committed BEFORE this publishes, so a publish failure only leaves the
// intent pending for the recovery pump — it never creates a second side effect.
//
// Publish and the outbox published-stamp are separate operations, so a crash
// between them republishes the identical intent. Every publish therefore
// carries the dispatch ref as the JetStream message id, which makes the stream
// itself drop the duplicate inside its duplicate window. That is a first line
// of defense, not the guarantee: the window is finite, so the connector's own
// dispatched->executing barrier and its dispatch_ref inbox dedup remain the
// authority on executing a redelivered intent exactly once.
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

// PublishDispatch publishes one durable dispatch intent to JetStream under the
// intent's dispatch ref as the message id (the stream's dedup key).
func (p *NATSPublisher) PublishDispatch(ctx context.Context, message DispatchMessage) error {
	if message.DispatchRef == "" {
		return errors.New("a dispatch intent without a dispatch ref carries no dedup id and must not be published")
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	_, err = p.js.Publish(p.subject, payload, nats.Context(ctx), nats.MsgId(message.DispatchRef))
	return err
}
