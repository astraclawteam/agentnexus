// Package host runs a connector in a constrained, isolated execution host. It
// speaks a stable, bounded, versioned RPC to a connector process or container,
// derives a sandbox policy from the connector's manifest-derived Product Pack
// and Customer Binding, and — through the supervisor — turns ANY connector
// failure (panic, timeout, oversized output, policy violation, malformed RPC,
// digest mismatch) into a bounded Result that can never crash the caller.
//
// The connector-internal wire form of this protocol is mirrored in
// api/proto/agentnexus/connectors/v1/connectors.proto (HostConnectorRequest /
// HostConnectorResponse). This package is the authoritative Go form.
package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
)

// ProtocolVersion is the stable connector-host RPC version. Both peers pin it;
// a mismatch is a bounded rejection, never a best-effort decode.
const ProtocolVersion = "connector.host/v1"

const (
	// MaxRequestBytes bounds one host->connector request envelope so a hostile
	// or buggy peer can never force an unbounded allocation on decode.
	MaxRequestBytes = 1 << 20 // 1 MiB
	// MaxResponseBytes is the absolute ceiling for one connector->host response
	// envelope. A per-operation Policy may bound the response tighter still.
	MaxResponseBytes = 1 << 20 // 1 MiB
)

// Protocol sentinels. Callers match these with errors.Is.
var (
	// ErrProtocolVersion marks an envelope that does not pin ProtocolVersion.
	ErrProtocolVersion = errors.New("connector host protocol version mismatch")
	// ErrEnvelopeTooLarge marks an envelope larger than its byte ceiling. The
	// decoder rejects it through a bounded reader, never by buffering it whole.
	ErrEnvelopeTooLarge = errors.New("connector host envelope exceeds size limit")
	// ErrMalformedEnvelope marks an envelope that is not well-formed or is
	// missing a required field.
	ErrMalformedEnvelope = errors.New("connector host envelope malformed")
)

// Status is the bounded connector-operation status. It mirrors the
// connectors/v1 ConnectorStatus enum and extends it with host-enforced bounded
// signals (DeniedPolicy, ResourceExhausted, ExecutionUncertain) while keeping the
// existing values stable. The host-enforced signals are host-authored and never
// connector-reportable; they are Go-only and are NOT part of the connectors/v1
// wire enum, so adding one is not a public-contract change.
type Status int

const (
	// StatusUnspecified is the zero value; a result must never carry it.
	StatusUnspecified Status = iota
	// StatusSucceeded is a bounded, well-formed successful result.
	StatusSucceeded
	// StatusDenied is a connector-reported denial (authorization/precondition).
	StatusDenied
	// StatusFailed is a DEFINITE technical failure with no committed side effect:
	// either a connector-REPORTED failure verdict (the connector ran and returned
	// Failed in its response), or a host-detected PRE-dispatch failure evaluated
	// BEFORE the connector was dispatched (a required credential could not be
	// acquired, or the request envelope was invalid). A POST-dispatch abnormal
	// outcome, where the side effect may already have committed, is
	// StatusExecutionUncertain — never this.
	StatusFailed
	// StatusWaitingExternalReceipt mirrors the connectors/v1 value: a write is
	// pending an external receipt.
	StatusWaitingExternalReceipt
	// StatusDeniedPolicy is a host-enforced policy denial evaluated before the
	// connector runs (filesystem escape, undeclared egress, digest mismatch).
	StatusDeniedPolicy
	// StatusResourceExhausted is a host-enforced resource bound (wall-clock or
	// CPU budget exceeded, memory ceiling, oversized output).
	StatusResourceExhausted
	// StatusExecutionUncertain is a host-enforced signal that the connector was
	// dispatched (or dispatch was attempted) but the host obtained no bounded
	// verdict: an adapter panic, a transport/dispatch failure, a post-dispatch
	// cancellation, or a malformed response. The external side effect MAY have
	// committed, so this is NOT a failure — the caller must reconcile and must
	// never assume either success or failure. Like DeniedPolicy/ResourceExhausted
	// it is host-authored and never connector-reportable.
	StatusExecutionUncertain
)

// String renders a stable, non-secret label for audit and logs.
func (s Status) String() string {
	switch s {
	case StatusSucceeded:
		return "succeeded"
	case StatusDenied:
		return "denied"
	case StatusFailed:
		return "failed"
	case StatusWaitingExternalReceipt:
		return "waiting_external_receipt"
	case StatusDeniedPolicy:
		return "denied_policy"
	case StatusResourceExhausted:
		return "resource_exhausted"
	case StatusExecutionUncertain:
		return "execution_uncertain"
	default:
		return "unspecified"
	}
}

// valid reports whether s is a status a connector may legitimately report in a
// response envelope. The host-only bounded signals (DeniedPolicy,
// ResourceExhausted) and the zero value are NOT connector-reportable: the host
// authors those itself.
func (s Status) valid() bool {
	switch s {
	case StatusSucceeded, StatusDenied, StatusFailed, StatusWaitingExternalReceipt:
		return true
	default:
		return false
	}
}

// FileAccess is one filesystem path an operation declares it will touch. The
// host validates every declared access against the sandbox roots before
// dispatch; the connector receives only paths that passed.
type FileAccess struct {
	Path  string `json:"path"`
	Write bool   `json:"write"`
}

// NetworkTarget is one egress endpoint an operation declares it will reach. The
// host validates every target against the manifest-derived egress allow-list
// before dispatch.
type NetworkTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// SecretGrant carries ONLY the non-secret metadata of an operation-scoped Secret
// Handle to the connector. The connector redeems it at the Secret Provider; the
// host never places a master credential or derived material in a grant.
type SecretGrant struct {
	HandleID        string `json:"handle_id"`
	ConnectorRef    string `json:"connector_ref"`
	Resource        string `json:"resource"`
	Operation       string `json:"operation"`
	Action          string `json:"action"`
	Version         string `json:"version"`
	ExpiresAtUnixMS int64  `json:"expires_at_unix_ms"`
	SingleUse       bool   `json:"single_use"`
}

// SecretGrantFromHandle projects a Secret Handle onto the non-secret grant the
// connector receives. It copies only opaque metadata; a Handle carries no secret
// material, so neither does the grant.
func SecretGrantFromHandle(h secretprovider.Handle) *SecretGrant {
	scope := h.Scope()
	return &SecretGrant{
		HandleID:        h.ID(),
		ConnectorRef:    scope.ConnectorRef,
		Resource:        scope.Resource,
		Operation:       scope.Operation,
		Action:          scope.Action,
		Version:         h.Version(),
		ExpiresAtUnixMS: h.ExpiresAt().UnixMilli(),
		SingleUse:       h.SingleUse(),
	}
}

// HostRequest is the bounded, versioned envelope the host speaks to a connector.
type HostRequest struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	Capability      string          `json:"capability"`
	Resource        string          `json:"resource"`
	Operation       string          `json:"operation"`
	Action          string          `json:"action"`
	Input           json.RawMessage `json:"input,omitempty"`
	Filesystem      []FileAccess    `json:"filesystem,omitempty"`
	Network         []NetworkTarget `json:"network,omitempty"`
	Secret          *SecretGrant    `json:"secret,omitempty"`
	DeadlineUnixMS  int64           `json:"deadline_unix_ms,omitempty"`
	MaxOutputBytes  int             `json:"max_output_bytes,omitempty"`
}

// Validate enforces the bounded envelope invariants: the pinned protocol
// version, a request id, and a non-negative output ceiling.
func (r *HostRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: nil request", ErrMalformedEnvelope)
	}
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: got %q want %q", ErrProtocolVersion, r.ProtocolVersion, ProtocolVersion)
	}
	if r.RequestID == "" {
		return fmt.Errorf("%w: request_id is required", ErrMalformedEnvelope)
	}
	if r.MaxOutputBytes < 0 {
		return fmt.Errorf("%w: max_output_bytes must not be negative", ErrMalformedEnvelope)
	}
	return nil
}

// HostResponse is the bounded, versioned envelope a connector returns.
type HostResponse struct {
	ProtocolVersion string          `json:"protocol_version"`
	RequestID       string          `json:"request_id"`
	Status          Status          `json:"status"`
	Output          json.RawMessage `json:"output,omitempty"`
	OutputHash      string          `json:"output_hash,omitempty"`
	Truncated       bool            `json:"truncated,omitempty"`
	Error           string          `json:"error,omitempty"`
}

// Validate enforces the response envelope invariants: the pinned protocol
// version and a connector-reportable status.
func (r *HostResponse) Validate() error {
	if r == nil {
		return fmt.Errorf("%w: nil response", ErrMalformedEnvelope)
	}
	if r.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: got %q want %q", ErrProtocolVersion, r.ProtocolVersion, ProtocolVersion)
	}
	if !r.Status.valid() {
		return fmt.Errorf("%w: status %d is not connector-reportable", ErrMalformedEnvelope, r.Status)
	}
	return nil
}

// EncodeHostRequest marshals a request and refuses to emit one larger than the
// request ceiling.
func EncodeHostRequest(req *HostRequest) ([]byte, error) {
	return encodeBounded(req, MaxRequestBytes)
}

// EncodeHostResponse marshals a response and refuses to emit one larger than the
// response ceiling.
func EncodeHostResponse(resp *HostResponse) ([]byte, error) {
	return encodeBounded(resp, MaxResponseBytes)
}

// DecodeHostRequest decodes a request from a bounded reader over data. It never
// buffers more than the request ceiling: an oversized document is rejected as
// ErrEnvelopeTooLarge without an unbounded allocation, and a garbage document is
// rejected as ErrMalformedEnvelope.
func DecodeHostRequest(data []byte) (*HostRequest, error) {
	var req HostRequest
	if err := decodeBounded(data, MaxRequestBytes, &req); err != nil {
		return nil, err
	}
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return &req, nil
}

// DecodeHostResponse decodes a response from a bounded reader over data.
func DecodeHostResponse(data []byte) (*HostResponse, error) {
	var resp HostResponse
	if err := decodeBounded(data, MaxResponseBytes, &resp); err != nil {
		return nil, err
	}
	if err := resp.Validate(); err != nil {
		return nil, err
	}
	return &resp, nil
}

func encodeBounded(v any, limit int) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("%w: %d > %d", ErrEnvelopeTooLarge, len(raw), limit)
	}
	return raw, nil
}

// decodeBounded reads at most limit+1 bytes through an io.LimitReader so a
// document larger than the ceiling is detected and rejected without buffering
// the whole thing, then strictly decodes the bounded slice.
func decodeBounded(data []byte, limit int, out any) error {
	limited := io.LimitReader(bytes.NewReader(data), int64(limit)+1)
	bounded, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	if len(bounded) > limit {
		return fmt.Errorf("%w: %d > %d", ErrEnvelopeTooLarge, len(bounded), limit)
	}
	dec := json.NewDecoder(bytes.NewReader(bounded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformedEnvelope, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: trailing data after envelope", ErrMalformedEnvelope)
	}
	return nil
}
