package runtime

// host_adapter.go is the GA connector-qualification core: a runtime-backed
// host.Adapter that lets a generic connector family (http/openapi, db-readonly,
// file/s3, webhook) run through the isolated host (internal/connectors/host) and
// therefore through both the central Worker (Task 5) and the outbound Connector
// Agent (Task 6) unchanged. The host package does NOT import runtime, so a
// runtime-backed adapter lives here with no import cycle.
//
// Authority boundary (frozen): the connector redeems the operation-scoped Secret
// Handle for DERIVED material and NEVER receives a master credential; connector
// topology (connector instance id, endpoint, table/API path, resource-internal
// key, credential) NEVER reaches HostResponse.Output (it becomes the hash-bound
// ActionReceipt result). The supervisor bounds every outcome; this adapter only
// translates the bounded HostRequest into a family operation and the family's
// bounded verdict back into a HostResponse.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	connector "github.com/astraclawteam/agentnexus/sdk/go/connector"
	secretprovider "github.com/astraclawteam/agentnexus/sdk/go/secretprovider"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/connectors/host"
)

// Family-execution sentinels. Each maps to a bounded, connector-reportable host
// status (never a host-authored signal): the read-only/traversal/undeclared
// classes are DENIALS (StatusDenied); the schema/rate classes are definite
// technical FAILURES (StatusFailed). None is ever returned raw to an Agent.
var (
	// ErrReadOnlyFamily marks a write/DDL/DML intent presented to the strictly
	// read-only database family. It is refused, never executed (StatusDenied).
	ErrReadOnlyFamily = errors.New("read-only connector family refuses a write operation")
	// ErrPathTraversal marks an object key that escapes its root (".." / absolute
	// / volume escape). The file family refuses it fail-closed (StatusDenied).
	ErrPathTraversal = errors.New("object key escapes the connector sandbox root")
	// ErrUndeclaredEndpoint marks a webhook target that is not one of the binding's
	// declared endpoints. The webhook writes ONLY to declared endpoints (StatusDenied).
	ErrUndeclaredEndpoint = errors.New("webhook target is not a declared endpoint")
	// ErrACLInvalidated marks a source that denied or deleted the resource (a 403 /
	// 404): the family fails closed with no stale data (StatusDenied).
	ErrACLInvalidated = errors.New("connector source denied or deleted the resource")
	// ErrSchemaInvalid marks a response missing a declared required field: it does
	// not satisfy the capability's output schema (StatusFailed).
	ErrSchemaInvalid = errors.New("connector response does not satisfy the declared output schema")
	// ErrRateLimited marks a rate-limit (HTTP 429) whose bounded Retry-After retries
	// were exhausted (StatusFailed).
	ErrRateLimited = errors.New("connector rate-limit retries exhausted")
	// ErrCapabilityUnknown marks an operation whose capability is not declared by
	// the pinned pack (StatusDenied — never executed).
	ErrCapabilityUnknown = errors.New("operation capability is not declared by the product pack")
	// ErrUndeclaredResponseField marks a response field the capability's field
	// policy never declared (StatusFailed) — connector output may carry only
	// declared semantic fields.
	ErrUndeclaredResponseField = errors.New("connector response carries an undeclared field")
)

// SecretRedeemer redeems an operation-scoped Secret Handle for its DERIVED,
// operation-scoped material. *secrets.Client satisfies it. A connector NEVER
// receives a master credential: it redeems the grant for one-way-derived
// material valid only for the handle's exact scope/version/lifetime.
type SecretRedeemer interface {
	Redeem(ctx context.Context, handle secretprovider.Handle, scope secretprovider.Scope) (secretprovider.Secret, error)
}

// FamilyRequest is the bounded, resolved input one connector family adapter
// executes over its injected client port. Resource/Operation/Action are the
// server-side resolved coordinates (never Agent-supplied); Auth is the DERIVED
// material (never a master credential); Capability and FieldPolicy drive schema
// validation and field masking; Endpoints are the binding's declared endpoints
// (the webhook writes only to these).
type FamilyRequest struct {
	Capability  connector.Capability
	FieldPolicy connector.FieldPolicy
	Resource    string
	Operation   string
	Action      string
	Input       json.RawMessage
	Auth        string
	Endpoints   []connector.Endpoint
}

// FamilyResponse is the bounded outcome of one family operation. Output is
// topology-free and schema-shaped (it becomes the hash-bound ActionReceipt
// result); Status is connector-reportable. A family adapter returns a non-nil
// error ONLY for an unbounded transport/deadline failure the supervisor must
// classify; every family-level verdict (denied/failed/succeeded) is a Status.
type FamilyResponse struct {
	Status host.Status
	Output json.RawMessage
	Reason string
}

// FamilyAdapter executes one connector-family operation over an injected client
// port. It is the single connector-execution engine per family; the host adapter
// selects it and the supervisor bounds it. The four generic families
// (http_openapi.go, db_readonly.go, file_storage.go, webhook.go) implement it.
type FamilyAdapter interface {
	Name() string
	Execute(ctx context.Context, req FamilyRequest) (FamilyResponse, error)
}

// ConnectorHostAdapter is the runtime-backed host.Adapter. It redeems the
// operation-scoped Secret Handle for derived material, resolves the pack
// capability, dispatches to the bound family adapter and maps the family's
// bounded verdict back into a topology-free HostResponse. One instance binds one
// connector product (pack + binding + family + injected client + redeemer).
type ConnectorHostAdapter struct {
	family   FamilyAdapter
	redeemer SecretRedeemer
	pack     connector.ProductPack
	binding  connector.CustomerBinding
}

// NewConnectorHostAdapter binds a family adapter (over its injected client) to a
// pack/binding and a secret redeemer. A nil family is a programming error; a nil
// redeemer is permitted only for a family that needs no credential.
func NewConnectorHostAdapter(family FamilyAdapter, redeemer SecretRedeemer, pack connector.ProductPack, binding connector.CustomerBinding) *ConnectorHostAdapter {
	return &ConnectorHostAdapter{family: family, redeemer: redeemer, pack: pack, binding: binding}
}

// Name identifies the bound family for audit (e.g. "http_openapi").
func (a *ConnectorHostAdapter) Name() string {
	if a == nil || a.family == nil {
		return "connector"
	}
	return a.family.Name()
}

// Dispatch runs one connector operation. It redeems the grant for derived
// material (never a master credential; fails closed if a grant is present but no
// redeemer is configured or the redeem is refused), resolves the pack capability,
// executes the family over its injected client and returns a bounded,
// topology-free HostResponse. A transport/deadline error is returned to the
// supervisor to classify (deadline -> resource_exhausted; other -> uncertain).
func (a *ConnectorHostAdapter) Dispatch(ctx context.Context, _ host.Policy, req *host.HostRequest) (*host.HostResponse, error) {
	if a == nil || a.family == nil {
		return nil, errors.New("connector host adapter has no family")
	}
	// Redeem the operation-scoped Secret Handle for DERIVED material. The master
	// credential never reaches the connector; a required-but-unresolvable secret
	// fails closed as a bounded denial, never a silent proceed-without-credential.
	auth := ""
	if req.Secret != nil {
		if a.redeemer == nil {
			return a.denied(req, "credential required but connector has no secret redeemer"), nil
		}
		secret, err := a.redeemGrant(ctx, req.Secret)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return nil, err // let the supervisor classify a deadline/cancel
			}
			return a.denied(req, "secret handle redeem refused"), nil
		}
		auth = secret.Reveal()
	}

	capability, ok := a.capability(req.Capability)
	if !ok {
		return a.denied(req, "undeclared capability"), nil
	}

	fresp, err := a.family.Execute(ctx, FamilyRequest{
		Capability:  capability,
		FieldPolicy: a.pack.FieldPolicy,
		Resource:    req.Resource,
		Operation:   req.Operation,
		Action:      req.Action,
		Input:       req.Input,
		Auth:        auth,
		Endpoints:   a.binding.Endpoints,
	})
	if err != nil {
		return nil, err // transport/deadline: the supervisor authors the bounded signal
	}
	return &host.HostResponse{
		ProtocolVersion: host.ProtocolVersion,
		RequestID:       req.RequestID,
		Status:          fresp.Status,
		Output:          fresp.Output,
		Error:           fresp.Reason,
	}, nil
}

// denied builds a bounded StatusDenied response. The reason is a coded,
// topology-free string safe for the audit trail.
func (a *ConnectorHostAdapter) denied(req *host.HostRequest, reason string) *host.HostResponse {
	return &host.HostResponse{
		ProtocolVersion: host.ProtocolVersion,
		RequestID:       req.RequestID,
		Status:          host.StatusDenied,
		Error:           reason,
	}
}

// capability resolves a declared capability by name from the pinned pack.
func (a *ConnectorHostAdapter) capability(name string) (connector.Capability, bool) {
	for _, c := range a.pack.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return connector.Capability{}, false
}

// handleView mirrors the secretprovider handle's safe (non-secret) serialized
// form so a SecretGrant (host-side opaque metadata) can be rebuilt into a
// redeemable secretprovider.Handle. A rebuilt handle is only a reference: the
// provider re-checks scope, version, expiry and single-use on redeem, so nothing
// here grants material by itself.
type handleView struct {
	ID        string               `json:"handle_id"`
	Scope     secretprovider.Scope `json:"scope"`
	Version   string               `json:"version"`
	IssuedAt  time.Time            `json:"issued_at"`
	ExpiresAt time.Time            `json:"expires_at"`
	SingleUse bool                 `json:"single_use"`
}

// redeemGrant rebuilds the redeemable handle from the bounded grant and redeems
// it at the provider for derived material under the grant's exact scope.
func (a *ConnectorHostAdapter) redeemGrant(ctx context.Context, grant *host.SecretGrant) (secretprovider.Secret, error) {
	scope := secretprovider.Scope{
		ConnectorRef: grant.ConnectorRef,
		Resource:     grant.Resource,
		Operation:    grant.Operation,
		Action:       grant.Action,
	}
	expires := time.UnixMilli(grant.ExpiresAtUnixMS).UTC()
	view := handleView{
		ID:        grant.HandleID,
		Scope:     scope,
		Version:   grant.Version,
		IssuedAt:  expires.Add(-time.Minute),
		ExpiresAt: expires,
		SingleUse: grant.SingleUse,
	}
	raw, err := json.Marshal(view)
	if err != nil {
		return secretprovider.Secret{}, err
	}
	var handle secretprovider.Handle
	if err := json.Unmarshal(raw, &handle); err != nil {
		return secretprovider.Secret{}, fmt.Errorf("rebuild secret handle: %w", err)
	}
	return a.redeemer.Redeem(ctx, handle, scope)
}

// --- shared read pipeline (http/db/file) -----------------------------------

// readRecord is one normalized, business-semantic record a read family fetched.
// It carries only declared semantic fields — never connector topology.
type readRecord map[string]any

// sourceMetadata is the authoritative source/version/freshness a read surfaces
// (the read/postcondition-probe metadata). Source is a business-semantic
// authority identity (e.g. "system_of_record"), never a connector endpoint,
// table or path.
type sourceMetadata struct {
	Source         string
	SourceVersion  int64
	Authority      string
	FreshnessBound time.Duration
	ObjectVersion  string // file/s3: the object version-id/ETag as the source version
}

// readOutput is the topology-free normalized output of a read family. It becomes
// the hash-bound ActionReceipt result: masked records plus source/version/
// freshness metadata, and nothing that identifies the connector or its topology.
type readOutput struct {
	Records       []readRecord `json:"records"`
	Source        string       `json:"source"`
	SourceVersion int64        `json:"source_version"`
	Authority     string       `json:"authority"`
	FreshUntil    time.Time    `json:"fresh_until"`
	ObjectVersion string       `json:"object_version,omitempty"`
}

// declaredFields returns the declared semantic field set (the pack field
// policy's classifications) and the subset that must be redacted (masked). The
// field policy is the customer-agnostic output-schema authority for the generic
// families: a response may carry only declared fields, and redacted ones are
// dropped before the output is hash-bound.
func declaredFields(fp connector.FieldPolicy) (declared map[string]bool, redacted map[string]bool) {
	declared = map[string]bool{}
	redacted = map[string]bool{}
	for _, c := range fp.Classifications {
		declared[c.Field] = true
		if c.Redacted || fp.DefaultRedacted {
			redacted[c.Field] = true
		}
	}
	return declared, redacted
}

// maskAndValidate enforces the schema/field contract on one page of fetched
// records and returns the masked records. Every record key must be a declared
// semantic field (else ErrUndeclaredResponseField); every declared NON-redacted
// field must be present (else ErrSchemaInvalid); every redacted field is dropped
// so the sensitive value never reaches the hash-bound output.
func maskAndValidate(records []readRecord, fp connector.FieldPolicy) ([]readRecord, error) {
	declared, redacted := declaredFields(fp)
	out := make([]readRecord, 0, len(records))
	for _, rec := range records {
		for key := range rec {
			if !declared[key] {
				return nil, fmt.Errorf("%w: %q", ErrUndeclaredResponseField, key)
			}
		}
		for field := range declared {
			if redacted[field] {
				continue
			}
			if _, ok := rec[field]; !ok {
				return nil, fmt.Errorf("%w: missing required field %q", ErrSchemaInvalid, field)
			}
		}
		masked := make(readRecord, len(rec))
		for key, value := range rec {
			if redacted[key] {
				continue
			}
			masked[key] = value
		}
		out = append(out, masked)
	}
	return out, nil
}

// buildReadResponse assembles a bounded, topology-free success response from the
// already-masked aggregated records and the source metadata. Standard-encoder
// map marshalling is key-sorted, so the output bytes — and therefore the
// ActionReceipt result_hash — are deterministic across the central and outbound
// topologies. FreshUntil is computed from a fixed observation instant so the two
// topologies produce byte-identical output.
func buildReadResponse(records []readRecord, meta sourceMetadata, at time.Time) (FamilyResponse, error) {
	out := readOutput{
		Records:       records,
		Source:        meta.Source,
		SourceVersion: meta.SourceVersion,
		Authority:     meta.Authority,
		FreshUntil:    at.Add(meta.FreshnessBound),
		ObjectVersion: meta.ObjectVersion,
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return FamilyResponse{}, err
	}
	return FamilyResponse{Status: host.StatusSucceeded, Output: raw}, nil
}

// readFreshnessWindow is the freshness bound a read surfaces for its
// source/version/freshness metadata. It is a fixed, documented window so the two
// execution topologies produce byte-identical output.
const readFreshnessWindow = 5 * time.Minute

// pageData is one page a read family fetched, normalized across the three read
// families (http/db/file). The shared pipeline consumes it uniformly.
type pageData struct {
	records       []readRecord
	next          string
	rateLimited   bool
	retryAfter    time.Duration
	denied        bool // ACL/deletion (403/404/forbidden) -> fail closed, no stale data
	failed        bool
	failReason    string
	source        string
	sourceVersion int64
	authority     string
	objectVersion string
}

// pageFetcher fetches one page for the given continuation token. Each read family
// wraps its injected client in a pageFetcher; the shared pipeline owns
// pagination, retry, ACL/deletion, schema/masking and assembly.
type pageFetcher func(ctx context.Context, token string) (pageData, error)

// runReadPipeline is the shared read pipeline for the http/db/file families:
// follow the continuation token until exhausted (aggregating), honor a rate
// limit with bounded Retry-After retries, fail closed on ACL/deletion, convert a
// deadline/transport error into a bounded failure, validate + mask every page
// against the field policy, and assemble a topology-free response with the
// authoritative source/version/freshness metadata.
func runReadPipeline(ctx context.Context, fetch pageFetcher, fp connector.FieldPolicy, sleep func(context.Context, time.Duration) error, now func() time.Time) (FamilyResponse, error) {
	var all []readRecord
	meta := sourceMetadata{FreshnessBound: readFreshnessWindow}
	haveMeta := false
	token := ""
	for page := 0; page < maxPages; page++ {
		var data pageData
		var err error
		for retry := 0; ; retry++ {
			data, err = fetch(ctx, token)
			if err != nil {
				if isDeadline(err) {
					return FamilyResponse{Status: host.StatusFailed, Reason: "operation deadline exceeded"}, nil
				}
				return FamilyResponse{Status: host.StatusFailed, Reason: "connector client error"}, nil
			}
			if data.rateLimited {
				if retry >= maxRateRetries {
					return FamilyResponse{Status: host.StatusFailed, Reason: "rate-limit retries exhausted"}, nil
				}
				if serr := sleep(ctx, data.retryAfter); serr != nil {
					return FamilyResponse{Status: host.StatusFailed, Reason: "deadline during rate-limit backoff"}, nil
				}
				continue
			}
			break
		}
		if data.denied {
			return FamilyResponse{Status: host.StatusDenied, Reason: "source denied or deleted the resource"}, nil
		}
		if data.failed {
			return FamilyResponse{Status: host.StatusFailed, Reason: defaultReason(data.failReason, "connector read failed")}, nil
		}
		masked, verr := maskAndValidate(data.records, fp)
		if verr != nil {
			return FamilyResponse{Status: host.StatusFailed, Reason: "response failed output schema validation"}, nil
		}
		all = append(all, masked...)
		if !haveMeta && data.source != "" {
			meta.Source = data.source
			meta.SourceVersion = data.sourceVersion
			meta.Authority = data.authority
			meta.ObjectVersion = data.objectVersion
			haveMeta = true
		}
		token = data.next
		if token == "" {
			break
		}
	}
	return buildReadResponse(all, meta, now())
}

// toRecords converts an injected client's rows into normalized readRecords.
func toRecords(in []map[string]any) []readRecord {
	out := make([]readRecord, 0, len(in))
	for _, r := range in {
		out = append(out, readRecord(r))
	}
	return out
}

// defaultReason returns s, or fallback when s is blank.
func defaultReason(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
