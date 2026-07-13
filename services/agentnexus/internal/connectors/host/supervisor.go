package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
)

// errAdapterPanic marks a panic recovered from inside an adapter dispatch. The
// supervisor maps it to a bounded StatusFailed; it never propagates.
var errAdapterPanic = errors.New("connector adapter panicked")

// maxReasonBytes bounds a Result.Reason so a hostile connector error string can
// never bloat an audit record.
const maxReasonBytes = 512

// Adapter runs one connector operation under a Policy and returns its response
// or an error. A process adapter runs the connector as a bounded child process;
// a container adapter runs it in a locked-down container. The supervisor — never
// the adapter — is the single place that guarantees a bounded Result.
type Adapter interface {
	Name() string
	Dispatch(ctx context.Context, policy Policy, req *HostRequest) (*HostResponse, error)
}

// SecretBroker yields an operation-scoped, single-use Secret Handle for a
// credential reference. It never yields a master credential.
// internal/secrets.Client satisfies it directly.
type SecretBroker interface {
	AcquireHandle(ctx context.Context, scope secretprovider.Scope, credentialRef string) (secretprovider.Handle, error)
}

// Config constructs a Supervisor for one connector instance.
type Config struct {
	Pack    connector.ProductPack
	Binding connector.CustomerBinding
	Adapter Adapter
	Secrets SecretBroker
	Options []DeriveOption
}

// Operation is one connector operation the caller asks the host to run.
type Operation struct {
	RequestID     string
	Capability    string
	Resource      string
	Operation     string
	Action        string
	Input         []byte
	Filesystem    []FileAccess
	Network       []NetworkTarget
	CredentialRef string
}

// Result is the bounded outcome of one operation. Every connector failure maps
// to a Status here; Run never returns an error and never propagates a panic.
type Result struct {
	Status     Status       `json:"status"`
	Output     []byte       `json:"output,omitempty"`
	OutputHash string       `json:"output_hash,omitempty"`
	Truncated  bool         `json:"truncated,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	Adapter    string       `json:"adapter,omitempty"`
	Audit      AuditContext `json:"audit"`
}

// AuditContext carries non-secret facts about one operation for the audit trail.
// It never carries master or derived secret material — only opaque handle
// metadata.
type AuditContext struct {
	ConnectorRef    string    `json:"connector_ref"`
	Capability      string    `json:"capability"`
	Resource        string    `json:"resource"`
	Operation       string    `json:"operation"`
	Action          string    `json:"action"`
	Isolation       string    `json:"isolation"`
	HandleID        string    `json:"handle_id,omitempty"`
	HandleScope     string    `json:"handle_scope,omitempty"`
	HandleSingleUse bool      `json:"handle_single_use,omitempty"`
	HandleExpiresAt time.Time `json:"handle_expires_at,omitempty"`
	OutputBytes     int       `json:"output_bytes"`
}

// Supervisor runs connector operations under a derived Policy through an Adapter,
// guaranteeing a bounded Result for every outcome.
type Supervisor struct {
	policy  Policy
	adapter Adapter
	secrets SecretBroker
}

// NewSupervisor derives the sandbox policy from the pack and binding and builds a
// supervisor. Policy derivation verifies the pack's content digest against the
// binding's pinned ProductRef.Digest, so a digest-swapped connector is refused
// here — before any execution is possible (ErrDigestMismatch).
func NewSupervisor(cfg Config) (*Supervisor, error) {
	if cfg.Adapter == nil {
		return nil, fmt.Errorf("%w: adapter is required", ErrPolicyInvalid)
	}
	policy, err := DerivePolicy(cfg.Pack, cfg.Binding, cfg.Options...)
	if err != nil {
		return nil, err
	}
	return &Supervisor{policy: policy, adapter: cfg.Adapter, secrets: cfg.Secrets}, nil
}

// Policy returns the derived sandbox policy for inspection.
func (s *Supervisor) Policy() Policy { return s.policy }

// Run executes one connector operation and always returns a bounded Result. Any
// failure mode — filesystem/egress policy violation, unresolved credential,
// wall-clock timeout, connector panic, malformed or oversized response — becomes
// a Status, never a propagated error and never a crash of the caller.
func (s *Supervisor) Run(ctx context.Context, op Operation) (result Result) {
	audit := AuditContext{
		ConnectorRef: s.policy.ConnectorRef,
		Capability:   op.Capability,
		Resource:     op.Resource,
		Operation:    op.Operation,
		Action:       op.Action,
		Isolation:    s.policy.Isolation,
	}
	adapterName := ""
	if s.adapter != nil {
		adapterName = s.adapter.Name()
	}

	// Panic firewall: nothing — not even a bug in the supervisor itself — escapes
	// Run as a panic. This is the core crash-isolation invariant.
	defer func() {
		if r := recover(); r != nil {
			result = bounded(StatusFailed, "supervisor recovered panic: "+fmt.Sprint(r), adapterName, audit)
		}
	}()

	// 1. Static policy: every declared filesystem access and network target is
	// checked against the manifest-derived sandbox BEFORE the connector runs. A
	// violation is denied without dispatching anything. (On the process adapter
	// path these checks are advisory; the container adapter enforces them at the
	// syscall level — see Policy.checkAccess and ProcessAdapter.)
	if err := s.policy.checkAccess(op.Filesystem, op.Network); err != nil {
		return bounded(StatusDeniedPolicy, err.Error(), adapterName, audit)
	}

	// 2. Secret handle: acquire an operation-scoped, single-use handle. The host
	// passes only the opaque handle to the connector and fails closed if a
	// credential is required but no broker is configured or the broker errors —
	// mirroring internal/connectors/runtime's discipline.
	var grant *SecretGrant
	if op.CredentialRef != "" {
		if s.secrets == nil {
			return bounded(StatusFailed, "credential required but no secret broker configured", adapterName, audit)
		}
		scope := secretprovider.Scope{
			ConnectorRef: s.policy.ConnectorRef,
			Resource:     op.Resource,
			Operation:    op.Operation,
			Action:       op.Action,
		}
		handle, err := s.secrets.AcquireHandle(ctx, scope, op.CredentialRef)
		if err != nil {
			return bounded(StatusFailed, "secret handle acquire failed: "+err.Error(), adapterName, audit)
		}
		grant = SecretGrantFromHandle(handle)
		audit.HandleID = handle.ID()
		audit.HandleScope = handle.Scope().String()
		audit.HandleSingleUse = handle.SingleUse()
		audit.HandleExpiresAt = handle.ExpiresAt()
	}

	// 3. Build and validate the bounded request envelope.
	req := &HostRequest{
		ProtocolVersion: ProtocolVersion,
		RequestID:       op.RequestID,
		Capability:      op.Capability,
		Resource:        op.Resource,
		Operation:       op.Operation,
		Action:          op.Action,
		Filesystem:      op.Filesystem,
		Network:         op.Network,
		Secret:          grant,
		MaxOutputBytes:  s.policy.MaxOutputBytes,
		DeadlineUnixMS:  time.Now().Add(s.policy.WallClock).UnixMilli(),
	}
	if len(op.Input) > 0 {
		req.Input = json.RawMessage(op.Input)
	}
	if err := req.Validate(); err != nil {
		return bounded(StatusFailed, "invalid host request: "+err.Error(), adapterName, audit)
	}

	// 4. Dispatch under a wall-clock timeout with an adapter-panic firewall. The
	// supervisor selects on the deadline itself, so even an adapter that ignores
	// cancellation can never make Run hang.
	resp, err := s.dispatch(ctx, req)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return bounded(StatusResourceExhausted, "wall-clock budget exceeded", adapterName, audit)
		case errors.Is(err, context.Canceled):
			return bounded(StatusFailed, "operation cancelled by caller", adapterName, audit)
		case errors.Is(err, errOutputOverflow):
			return boundedTruncated(nil, "connector output exceeded the policy ceiling", adapterName, audit)
		case errors.Is(err, errAdapterPanic):
			return bounded(StatusFailed, "connector panicked: "+err.Error(), adapterName, audit)
		default:
			return bounded(StatusFailed, "connector dispatch failed: "+err.Error(), adapterName, audit)
		}
	}

	// 5. Bound the response: validate the envelope, then cap the output. An
	// oversized output is truncated and reported as a bounded resource failure —
	// never buffered whole or returned as success.
	if err := resp.Validate(); err != nil {
		return bounded(StatusFailed, "malformed connector response: "+err.Error(), adapterName, audit)
	}
	output := []byte(resp.Output)
	if s.policy.MaxOutputBytes > 0 && len(output) > s.policy.MaxOutputBytes {
		return boundedTruncated(output[:s.policy.MaxOutputBytes], "connector output exceeded the policy ceiling", adapterName, audit)
	}
	audit.OutputBytes = len(output)
	return Result{
		Status:     resp.Status,
		Output:     output,
		OutputHash: hashOutput(output),
		Reason:     sanitizeReason(resp.Error),
		Adapter:    adapterName,
		Audit:      audit,
	}
}

// dispatch runs the adapter under a wall-clock deadline in a goroutine, recovers
// any adapter panic, and returns as soon as the adapter finishes or the deadline
// fires — whichever comes first. The result channel is buffered so the adapter
// goroutine can never leak when the deadline wins the race.
func (s *Supervisor) dispatch(ctx context.Context, req *HostRequest) (*HostResponse, error) {
	dctx, cancel := context.WithTimeout(ctx, s.policy.WallClock)
	defer cancel()

	type outcome struct {
		resp *HostResponse
		err  error
	}
	ch := make(chan outcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- outcome{nil, fmt.Errorf("%w: %v", errAdapterPanic, r)}
			}
		}()
		resp, err := s.adapter.Dispatch(dctx, s.policy, req)
		ch <- outcome{resp, err}
	}()

	select {
	case <-dctx.Done():
		return nil, dctx.Err()
	case o := <-ch:
		return o.resp, o.err
	}
}

// bounded builds a bounded Result with a sanitized reason.
func bounded(status Status, reason, adapter string, audit AuditContext) Result {
	return Result{Status: status, Reason: sanitizeReason(reason), Adapter: adapter, Audit: audit}
}

// boundedTruncated builds a bounded, truncated resource-exhausted Result.
func boundedTruncated(output []byte, reason, adapter string, audit AuditContext) Result {
	audit.OutputBytes = len(output)
	return Result{
		Status:     StatusResourceExhausted,
		Output:     output,
		OutputHash: hashOutput(output),
		Truncated:  true,
		Reason:     sanitizeReason(reason),
		Adapter:    adapter,
		Audit:      audit,
	}
}

func hashOutput(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sanitizeReason keeps a reason string safe for an audit record: it drops NUL
// bytes (this codebase forbids NUL reaching audit strings), replaces other
// control characters with spaces, and bounds the length.
func sanitizeReason(s string) string {
	if s == "" {
		return ""
	}
	s = strings.Map(func(r rune) rune {
		switch {
		case r == 0x00:
			return -1
		case r == '\t' || r == '\n':
			return ' '
		case r < 0x20 || r == 0x7f:
			return ' '
		default:
			return r
		}
	}, s)
	if len(s) > maxReasonBytes {
		// Truncate on a rune boundary so a multi-byte rune is never split, which
		// would leave invalid UTF-8 in an audit string.
		s = s[:maxReasonBytes]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
