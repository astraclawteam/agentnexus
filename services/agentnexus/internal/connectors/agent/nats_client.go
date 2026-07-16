package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/actions"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/worker"
	"github.com/nats-io/nats.go"
)

// OutboundConfig configures the agent's OUTBOUND mTLS NATS dial. The agent is a
// CLIENT: it only ever DIALS; it NEVER binds a listener. The plaintext token
// path is retired for production — mTLS is the only production transport.
type OutboundConfig struct {
	URL string
	TLS *tls.Config
}

// ConnectOutbound dials the central NATS/JetStream over the outbound-initiated
// mTLS session. nats.Secure pins the client to the provided *tls.Config (built
// by transportsecurity.Manager.ClientTLSConfig), so the session is mutually
// authenticated and works behind an inbound-deny firewall (the agent initiates
// every connection). A nil TLS config is refused: production never dials
// plaintext.
func ConnectOutbound(cfg OutboundConfig, opts ...nats.Option) (*nats.Conn, error) {
	if cfg.TLS == nil {
		return nil, errors.New("connector agent outbound dial requires an mTLS client config; refusing plaintext")
	}
	options := append([]nats.Option{nats.Secure(cfg.TLS)}, opts...)
	return nats.Connect(cfg.URL, options...)
}

// NATSDialer is the production Dialer: it dials the central NATS over the
// outbound mTLS session and returns a Transport. It binds no listener.
type NATSDialer struct {
	URL  string
	Opts []nats.Option
}

// Dial establishes the outbound session from the pinned mTLS client config.
func (d *NATSDialer) Dial(_ context.Context, tlsConfig *tls.Config) (Transport, error) {
	conn, err := ConnectOutbound(OutboundConfig{URL: d.URL, TLS: tlsConfig}, d.Opts...)
	if err != nil {
		return nil, err
	}
	return &natsTransport{conn: conn}, nil
}

type natsTransport struct{ conn *nats.Conn }

func (t *natsTransport) Connected() bool { return t.conn != nil && t.conn.IsConnected() }
func (t *natsTransport) Close() error {
	if t.conn != nil {
		t.conn.Close()
	}
	return nil
}

// --- central ActionPlane bridge over the outbound session -------------------

// SubjectActionPlane is the request/reply subject the agent's RemoteActionPlane
// calls and the central RESPONDER answers. Request/reply is itself outbound-
// initiated (the reply lands on the client's own inbox), so it works behind an
// inbound-deny firewall.
const SubjectActionPlane = "agentnexus.actions.connectoragent.plane"

// DefaultActionPlaneTimeout bounds one ActionPlane request/reply round trip.
const DefaultActionPlaneTimeout = 5 * time.Second

type planeMethod string

const (
	methodGetAction     planeMethod = "get_action"
	methodMarkExecuting planeMethod = "mark_executing"
	methodIngestReceipt planeMethod = "ingest_receipt"
	methodResultUnknown planeMethod = "mark_result_unknown"
)

type planeRequest struct {
	Method    planeMethod              `json:"method"`
	Principal runtime.PrincipalContext `json:"principal"`
	ActionRef string                   `json:"action_ref"`
	ResultID  string                   `json:"result_id,omitempty"`
	Receipt   *runtime.ActionReceipt   `json:"receipt,omitempty"`
}

type planeReply struct {
	Action  *actions.Action `json:"action,omitempty"`
	ErrCode string          `json:"err_code,omitempty"`
	ErrMsg  string          `json:"err_msg,omitempty"`
}

// RemoteActionPlane is the PRODUCTION worker.ActionPlane: it serializes the four
// authoritative Action-state calls as NATS request/reply over the SAME outbound-
// dialed connection. The central RESPONDER that answers these and calls the real
// *actions.Service is a central component NOT built in Task 6 (a deferred
// fail-closed seam, Task 7+); the integration test provides a real responder so
// the bridge is exercised end to end and is never hollow.
type RemoteActionPlane struct {
	conn    *nats.Conn
	subject string
	timeout time.Duration
}

// NewRemoteActionPlane builds the bridge over an established outbound connection.
func NewRemoteActionPlane(conn *nats.Conn, timeout time.Duration) *RemoteActionPlane {
	if timeout <= 0 {
		timeout = DefaultActionPlaneTimeout
	}
	return &RemoteActionPlane{conn: conn, subject: SubjectActionPlane, timeout: timeout}
}

func (r *RemoteActionPlane) call(ctx context.Context, req planeRequest) (actions.Action, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return actions.Action{}, errors.Join(actions.ErrUnavailable, err)
	}
	msg, err := r.conn.RequestWithContext(ctx, r.subject, payload)
	if err != nil {
		// A transport failure (a dropped session): transient, so the caller naks
		// and the durable pull redelivers.
		return actions.Action{}, errors.Join(actions.ErrUnavailable, err)
	}
	var reply planeReply
	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return actions.Action{}, errors.Join(actions.ErrUnavailable, err)
	}
	if err := decodePlaneError(reply); err != nil {
		return actions.Action{}, err
	}
	if reply.Action == nil {
		return actions.Action{}, errors.Join(actions.ErrUnavailable, errors.New("action plane reply carried no action"))
	}
	return *reply.Action, nil
}

func (r *RemoteActionPlane) GetAction(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	return r.call(ctx, planeRequest{Method: methodGetAction, Principal: principal, ActionRef: actionRef})
}

func (r *RemoteActionPlane) MarkExecuting(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	return r.call(ctx, planeRequest{Method: methodMarkExecuting, Principal: principal, ActionRef: actionRef})
}

func (r *RemoteActionPlane) IngestReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt) (actions.Action, error) {
	return r.call(ctx, planeRequest{Method: methodIngestReceipt, Principal: principal, ResultID: resultID, Receipt: &receipt, ActionRef: receipt.ActionRef})
}

func (r *RemoteActionPlane) MarkResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (actions.Action, error) {
	return r.call(ctx, planeRequest{Method: methodResultUnknown, Principal: principal, ActionRef: actionRef})
}

// ServeActionPlane is the central RESPONDER side of the bridge: it subscribes on
// SubjectActionPlane and answers each request by calling the underlying
// worker.ActionPlane (in production the real *actions.Service). This concrete
// responder is a deferred seam (Task 7+); the integration test wires it to a
// real actions.Service over real Postgres so the request/reply bridge is proven
// end to end. It returns an unsubscribe function.
func ServeActionPlane(conn *nats.Conn, plane worker.ActionPlane) (func() error, error) {
	if conn == nil || plane == nil {
		return nil, errors.New("ServeActionPlane requires a connection and an action plane")
	}
	sub, err := conn.Subscribe(SubjectActionPlane, func(msg *nats.Msg) {
		reply := serveOne(context.Background(), plane, msg.Data)
		payload, err := json.Marshal(reply)
		if err != nil {
			return
		}
		_ = msg.Respond(payload)
	})
	if err != nil {
		return nil, err
	}
	return sub.Unsubscribe, nil
}

func serveOne(ctx context.Context, plane worker.ActionPlane, data []byte) planeReply {
	var req planeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return planeReply{ErrCode: "unavailable", ErrMsg: err.Error()}
	}
	var action actions.Action
	var err error
	switch req.Method {
	case methodGetAction:
		action, err = plane.GetAction(ctx, req.Principal, req.ActionRef)
	case methodMarkExecuting:
		action, err = plane.MarkExecuting(ctx, req.Principal, req.ActionRef)
	case methodIngestReceipt:
		if req.Receipt == nil {
			return planeReply{ErrCode: "unavailable", ErrMsg: "ingest receipt request carried no receipt"}
		}
		action, err = plane.IngestReceipt(ctx, req.Principal, req.ResultID, *req.Receipt)
	case methodResultUnknown:
		action, err = plane.MarkResultUnknown(ctx, req.Principal, req.ActionRef)
	default:
		return planeReply{ErrCode: "unavailable", ErrMsg: "unknown action plane method"}
	}
	if err != nil {
		return planeReply{ErrCode: encodePlaneError(err), ErrMsg: err.Error()}
	}
	return planeReply{Action: &action}
}

func encodePlaneError(err error) string {
	switch {
	case errors.Is(err, actions.ErrNotFound):
		return "not_found"
	case errors.Is(err, actions.ErrForbiddenTransition):
		return "forbidden_transition"
	default:
		return "unavailable"
	}
}

func decodePlaneError(reply planeReply) error {
	switch reply.ErrCode {
	case "":
		return nil
	case "not_found":
		return actions.ErrNotFound
	case "forbidden_transition":
		return actions.ErrForbiddenTransition
	default:
		return errors.Join(actions.ErrUnavailable, errors.New(reply.ErrMsg))
	}
}
