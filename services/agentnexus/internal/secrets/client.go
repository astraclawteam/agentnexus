// Package secrets is the service-side client of the AgentNexus Secret Provider
// protocol (GA Task 3). The connector runtime uses it to acquire an
// operation-scoped Secret Handle and to redeem that handle for derived
// material; it never handles a master credential. Production readiness fails
// closed: when the configured provider is unreachable, CheckReady reports a
// hard error rather than falling back to plaintext or cached-master credentials.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
)

// DefaultHandleTTL bounds the lifetime the client requests for acquired
// handles. The provider clamps anything above secretprovider.MaxHandleTTL.
const DefaultHandleTTL = 2 * time.Minute

const (
	// maxWireBytes bounds one protocol message. A local peer cannot force
	// unbounded allocation by streaming an endless JSON document.
	maxWireBytes = 1 << 20
	// wireTimeout bounds one request/response exchange when the caller supplies
	// no deadline, so a stalled peer can never pin a goroutine or connection
	// forever.
	wireTimeout = 10 * time.Second
)

// Client acquires and redeems Secret Handles against a Secret Provider. The
// provider is transport-abstracted: an in-process reference provider, or a
// SocketProvider that speaks the protocol over an authenticated local
// connection, satisfy the same contract.
type Client struct {
	provider    secretprovider.Provider
	callerToken string
	ttl         time.Duration
	singleUse   bool
}

// Option configures a Client.
type Option func(*Client)

// WithHandleTTL requests a specific handle lifetime.
func WithHandleTTL(ttl time.Duration) Option {
	return func(c *Client) {
		if ttl > 0 {
			c.ttl = ttl
		}
	}
}

// WithSingleUse requests single-use handles (default true).
func WithSingleUse(single bool) Option {
	return func(c *Client) { c.singleUse = single }
}

// NewClient builds a Secret Provider client. callerToken is the local
// authentication secret presented to the provider on every call.
func NewClient(provider secretprovider.Provider, callerToken string, opts ...Option) *Client {
	client := &Client{
		provider:    provider,
		callerToken: callerToken,
		ttl:         DefaultHandleTTL,
		singleUse:   true,
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

// AcquireHandle issues an operation-scoped Secret Handle. It satisfies the
// connector runtime's secret-handle port. A missing provider fails closed.
func (c *Client) AcquireHandle(ctx context.Context, scope secretprovider.Scope, credentialRef string) (secretprovider.Handle, error) {
	if c == nil || c.provider == nil {
		return secretprovider.Handle{}, secretprovider.ErrProviderUnavailable
	}
	return c.provider.AcquireHandle(ctx, secretprovider.AcquireRequest{
		CallerToken:   c.callerToken,
		Scope:         scope,
		CredentialRef: credentialRef,
		TTL:           c.ttl,
		SingleUse:     c.singleUse,
	})
}

// Redeem exchanges a handle for its derived, operation-scoped material. The
// scope must match the handle's issued scope exactly.
func (c *Client) Redeem(ctx context.Context, handle secretprovider.Handle, scope secretprovider.Scope) (secretprovider.Secret, error) {
	if c == nil || c.provider == nil {
		return secretprovider.Secret{}, secretprovider.ErrProviderUnavailable
	}
	return c.provider.Redeem(ctx, secretprovider.RedeemRequest{
		CallerToken: c.callerToken,
		HandleID:    handle.ID(),
		Scope:       scope,
	})
}

// CheckReady is the production-readiness probe. It fails closed: a missing or
// unreachable Secret Provider is a hard error, never a silent downgrade to
// plaintext or cached-master credentials.
func (c *Client) CheckReady(ctx context.Context) error {
	if c == nil || c.provider == nil {
		return secretprovider.ErrProviderUnavailable
	}
	if err := c.provider.Ping(ctx); err != nil {
		if errors.Is(err, secretprovider.ErrProviderUnavailable) {
			return err
		}
		return errors.Join(secretprovider.ErrProviderUnavailable, err)
	}
	return nil
}

// Dialer opens one authenticated local connection to the Secret Provider. On
// Unix it dials a Unix-domain socket; on Windows a named pipe or a loopback
// token endpoint. The codec and caller authentication are identical regardless
// of transport — the SDK Provider contract abstracts it.
type Dialer func(ctx context.Context) (net.Conn, error)

// SocketProvider is a secretprovider.Provider that speaks the protocol over a
// local connection produced by a Dialer. Each call opens a connection,
// exchanges exactly one request/response and closes it.
type SocketProvider struct {
	dial Dialer
}

// NewSocketProvider builds a transport client over the given Dialer.
func NewSocketProvider(dial Dialer) *SocketProvider { return &SocketProvider{dial: dial} }

const (
	opAcquire = "acquire"
	opRedeem  = "redeem"
	opPing    = "ping"
)

type wireRequest struct {
	Op      string                         `json:"op"`
	Acquire *secretprovider.AcquireRequest `json:"acquire,omitempty"`
	Redeem  *secretprovider.RedeemRequest  `json:"redeem,omitempty"`
}

type wireResponse struct {
	Error    string          `json:"error,omitempty"`
	Handle   json.RawMessage `json:"handle,omitempty"`
	Material string          `json:"material,omitempty"`
}

// wireError pairs a stable wire code with its sentinel. The slice is ordered so
// encoding is deterministic; each sentinel is distinct so decoding is exact.
var wireErrorTable = []struct {
	code string
	err  error
}{
	{"unauthenticated", secretprovider.ErrUnauthenticated},
	{"invalid_request", secretprovider.ErrInvalidRequest},
	{"unknown_credential", secretprovider.ErrUnknownCredential},
	{"invalid_handle", secretprovider.ErrInvalidHandle},
	{"scope_mismatch", secretprovider.ErrScopeMismatch},
	{"expired", secretprovider.ErrHandleExpired},
	{"consumed", secretprovider.ErrHandleConsumed},
	{"revoked_version", secretprovider.ErrRevokedVersion},
	{"unavailable", secretprovider.ErrProviderUnavailable},
}

func encodeError(err error) string {
	for _, entry := range wireErrorTable {
		if errors.Is(err, entry.err) {
			return entry.code
		}
	}
	// Unknown failures fail closed as an outage.
	return "unavailable"
}

func decodeError(code string) error {
	for _, entry := range wireErrorTable {
		if entry.code == code {
			return entry.err
		}
	}
	return secretprovider.ErrProviderUnavailable
}

// AcquireHandle implements secretprovider.Provider over the transport.
func (s *SocketProvider) AcquireHandle(ctx context.Context, req secretprovider.AcquireRequest) (secretprovider.Handle, error) {
	var resp wireResponse
	if err := s.roundTrip(ctx, wireRequest{Op: opAcquire, Acquire: &req}, &resp); err != nil {
		return secretprovider.Handle{}, err
	}
	if resp.Error != "" {
		return secretprovider.Handle{}, decodeError(resp.Error)
	}
	var handle secretprovider.Handle
	if err := json.Unmarshal(resp.Handle, &handle); err != nil {
		return secretprovider.Handle{}, errors.Join(secretprovider.ErrProviderUnavailable, err)
	}
	return handle, nil
}

// Redeem implements secretprovider.Provider over the transport.
func (s *SocketProvider) Redeem(ctx context.Context, req secretprovider.RedeemRequest) (secretprovider.Secret, error) {
	var resp wireResponse
	if err := s.roundTrip(ctx, wireRequest{Op: opRedeem, Redeem: &req}, &resp); err != nil {
		return secretprovider.Secret{}, err
	}
	if resp.Error != "" {
		return secretprovider.Secret{}, decodeError(resp.Error)
	}
	// Derived material is non-empty by construction. A success response with no
	// material is a malformed/hostile reply; fail closed rather than hand back an
	// empty-but-valid Secret.
	if resp.Material == "" {
		return secretprovider.Secret{}, secretprovider.ErrProviderUnavailable
	}
	return secretprovider.SecretFromMaterial(resp.Material), nil
}

// Ping implements secretprovider.Provider over the transport.
func (s *SocketProvider) Ping(ctx context.Context) error {
	var resp wireResponse
	if err := s.roundTrip(ctx, wireRequest{Op: opPing}, &resp); err != nil {
		return err
	}
	if resp.Error != "" {
		return decodeError(resp.Error)
	}
	return nil
}

func (s *SocketProvider) roundTrip(ctx context.Context, req wireRequest, resp *wireResponse) error {
	if s == nil || s.dial == nil {
		return secretprovider.ErrProviderUnavailable
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return errors.Join(secretprovider.ErrProviderUnavailable, err)
	}
	defer conn.Close()
	// Honor the caller's deadline for the whole exchange so a Redeem with a
	// context deadline actually times out; otherwise bound it to wireTimeout.
	_ = conn.SetDeadline(wireDeadline(ctx))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return errors.Join(secretprovider.ErrProviderUnavailable, err)
	}
	if err := json.NewDecoder(io.LimitReader(conn, maxWireBytes)).Decode(resp); err != nil {
		return errors.Join(secretprovider.ErrProviderUnavailable, err)
	}
	return nil
}

// wireDeadline resolves the deadline for one exchange: the caller's context
// deadline when present, otherwise now+wireTimeout.
func wireDeadline(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	return time.Now().Add(wireTimeout)
}

// ServeConn handles exactly one request on a connection accepted from a local
// listener and delegates to the backing provider. It is the server half of the
// authenticated local protocol; the backing provider enforces authentication,
// scope, version, expiry and single-use.
func ServeConn(conn net.Conn, provider secretprovider.Provider) error {
	defer conn.Close()
	// Bound the exchange in time so a stalled peer cannot pin this goroutine or
	// connection forever, and derive a matching context for the provider call
	// instead of an unbounded context.Background.
	deadline := time.Now().Add(wireTimeout)
	_ = conn.SetDeadline(deadline)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	var req wireRequest
	// Bound the request size so an endless JSON document cannot exhaust memory.
	if err := json.NewDecoder(io.LimitReader(conn, maxWireBytes)).Decode(&req); err != nil {
		return err
	}
	resp := dispatch(ctx, provider, req)
	return json.NewEncoder(conn).Encode(resp)
}

func dispatch(ctx context.Context, provider secretprovider.Provider, req wireRequest) wireResponse {
	switch req.Op {
	case opPing:
		if err := provider.Ping(ctx); err != nil {
			return wireResponse{Error: encodeError(err)}
		}
		return wireResponse{}
	case opAcquire:
		if req.Acquire == nil {
			return wireResponse{Error: encodeError(secretprovider.ErrInvalidRequest)}
		}
		handle, err := provider.AcquireHandle(ctx, *req.Acquire)
		if err != nil {
			return wireResponse{Error: encodeError(err)}
		}
		raw, err := json.Marshal(handle)
		if err != nil {
			return wireResponse{Error: encodeError(secretprovider.ErrProviderUnavailable)}
		}
		return wireResponse{Handle: raw}
	case opRedeem:
		if req.Redeem == nil {
			return wireResponse{Error: encodeError(secretprovider.ErrInvalidRequest)}
		}
		secret, err := provider.Redeem(ctx, *req.Redeem)
		if err != nil {
			return wireResponse{Error: encodeError(err)}
		}
		return wireResponse{Material: secret.Reveal()}
	default:
		return wireResponse{Error: encodeError(secretprovider.ErrInvalidRequest)}
	}
}
