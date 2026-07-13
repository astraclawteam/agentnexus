// Package evidence is the GA Task 0D semantic evidence plane: it resolves
// business-semantic data needs to internal source bindings PRIVATELY, stages
// encrypted bounded content, and issues opaque evd_* handles whose full
// binding (tenant, actor, Agent release, org version, source version,
// purpose, content hash, authorization lineage, TTL and optional raw-content
// retention TTL) lives server-side only.
//
// Governed boundaries:
//
//   - Public contracts expose business-semantic data classes and opaque
//     handles, never connector instances, endpoints, table/API paths or
//     customer network topology — not in responses, not in errors, not in
//     audit details, not in log lines.
//   - A cache response always states source version and as-of time; it never
//     masquerades as real-time data. Serving staged (cached) content requires
//     the binding's EXPLICIT cached-read grant.
//   - Invalidated, revoked, expired and source-deleted handles fail CLOSED:
//     deny, never a stale fallback.
//   - Connector-backed data classes (source capability under the connector.
//     prefix, policy.IsConnectorCapability being the single source of truth)
//     require trust.Context.ConnectorCapabilityAllowed; AstraClaw/Xiaozhi
//     origins therefore never receive connector-backed evidence.
package evidence

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/policy"
)

// Decision values of the public read envelope (frozen PolicyDecision enum
// members emitted by this task).
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Errors. Handlers map sentinels onto fixed public envelopes; the joined
// detail is internal and never carries content or source topology.
var (
	// ErrInvalidRequest marks a malformed or expired request.
	ErrInvalidRequest = errors.New("invalid evidence request")
	// ErrDenied marks a fail-closed authorization denial. Unknown data classes
	// are deliberately indistinguishable from denials (no existence oracle on
	// the private registry).
	ErrDenied = errors.New("evidence request denied")
	// ErrNotFound marks a missing binding or handle on administrative
	// operations (never surfaced through Locate/Read, which deny instead).
	ErrNotFound = errors.New("evidence not found")
	// ErrContentTooLarge marks source content above the staging bound; the
	// request fails explicitly, content is never silently truncated.
	ErrContentTooLarge = errors.New("evidence content exceeds the staging bound")
	// ErrUnavailable marks a persistence, key, source or lineage outage;
	// callers fail closed.
	ErrUnavailable = errors.New("evidence service unavailable")
)

// Authorization is the credential-derived authorization envelope of the
// caller, resolved once at ingress (internal/trust) and never supplied by
// request JSON.
type Authorization struct {
	// OrgVersion is the sealed organization snapshot version pinned at
	// ingress.
	OrgVersion int64
	// ConnectorCapabilityAllowed reports whether this context may exercise
	// enterprise connector capability. AstraClaw/Xiaozhi origins never may.
	ConnectorCapabilityAllowed bool
}

// SourceBinding is one row of the PRIVATE semantic registry: it maps a
// business-semantic data class to its internal source. SourceRef is
// internal-only topology and never crosses the public plane.
type SourceBinding struct {
	TenantRef string
	ID        string
	DataClass string
	// SourceRef locates the source privately (it may be connector-shaped).
	SourceRef     string
	SourceVersion int64
	// AccessCapability is the business capability the caller needs, evaluated
	// through the neutral capability policy with the sealed org version.
	AccessCapability string
	// SourceCapability classifies the source plane; a connector. prefix marks
	// the binding connector-backed (policy.IsConnectorCapability).
	SourceCapability string
	ResourceType     string
	ResourceID       string
	// CachedReadAllowed is the EXPLICIT cached-read grant; default deny.
	CachedReadAllowed bool
	// RetentionTTL is the optional raw-content retention TTL (0 = none).
	RetentionTTL time.Duration
	Deleted      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// connectorBacked reports whether this binding resolves through the
// enterprise connector plane, using policy.IsConnectorCapability as the
// single source of truth.
func (b SourceBinding) connectorBacked() bool {
	return policy.IsConnectorCapability(policy.Capability(b.SourceCapability))
}

// Handle is the full SERVER-SIDE binding behind one opaque evd_* handle. The
// public EvidenceHandle DTO exposes only ref, data class, summary and expiry.
type Handle struct {
	TenantRef       string
	EvidenceRef     string
	PrincipalRef    string
	AgentClientRef  string
	AgentReleaseRef string
	OrgVersion      int64
	DataClass       string
	BindingID       string
	SourceVersion   int64
	Purpose         string
	// BusinessContextRef is the wc_* work-case handle the evidence belongs to.
	BusinessContextRef string
	// ContentHash is the sha256 (hex) of the normalized plaintext content.
	ContentHash  string
	ContentBytes int64
	RecordCount  int64
	// RecordOffset/PageLimit describe this handle's pagination window over the
	// staged records; continuation handles carry a non-zero offset.
	RecordOffset int64
	PageLimit    int64
	// ObjectKey addresses the ENCRYPTED staged content; KeyRef names the key
	// provider entry used to seal it (never key material).
	ObjectKey string
	KeyRef    string
	// AuthorizationRef is the audit-evidence reference of the locate decision;
	// Lineage is the full authorization lineage chain (refs only).
	AuthorizationRef  string
	Lineage           []string
	CachedReadAllowed bool
	StagedAt          time.Time
	ExpiresAt         time.Time
	// RetentionExpiresAt is the optional raw-content retention deadline (zero
	// = none): staged content is removed independently of the handle record.
	RetentionExpiresAt time.Time
	CreatedAt          time.Time
}

// HandleEventKind is the append-only handle lifecycle vocabulary.
type HandleEventKind string

const (
	// HandleEventRevoked marks an explicit authorization revocation.
	HandleEventRevoked HandleEventKind = "revoked"
	// HandleEventContentExpired marks raw-content retention expiry: the
	// staged content is removed while the handle metadata stays auditable.
	HandleEventContentExpired HandleEventKind = "content_expired"
)

func (k HandleEventKind) valid() bool {
	switch k {
	case HandleEventRevoked, HandleEventContentExpired:
		return true
	}
	return false
}

// HandleEvent is one append-only handle lifecycle row.
type HandleEvent struct {
	TenantRef   string
	ID          string
	EvidenceRef string
	Kind        HandleEventKind
	Reason      string
	Seq         int64
	CreatedAt   time.Time
}

// Store is the persistence port of the evidence plane. Handles are immutable
// and handle events are append-only (trigger-enforced in PostgreSQL);
// bindings are administrative rows whose source version advances on
// invalidation.
type Store interface {
	UpsertSourceBinding(ctx context.Context, binding SourceBinding) (SourceBinding, error)
	GetSourceBinding(ctx context.Context, tenantRef, dataClass string) (SourceBinding, error)
	// BumpSourceVersion advances the source version by one (invalidation).
	BumpSourceVersion(ctx context.Context, tenantRef, dataClass string, now time.Time) (SourceBinding, error)
	// MarkSourceDeleted tombstones a removed source.
	MarkSourceDeleted(ctx context.Context, tenantRef, dataClass string, now time.Time) (SourceBinding, error)
	CreateHandle(ctx context.Context, handle Handle) (Handle, error)
	GetHandle(ctx context.Context, tenantRef, evidenceRef string) (Handle, error)
	AppendHandleEvent(ctx context.Context, event HandleEvent) (HandleEvent, error)
	ListHandleEvents(ctx context.Context, tenantRef, evidenceRef string) ([]HandleEvent, error)
	// ListRetentionExpired lists at most limit handles whose raw-content
	// retention deadline passed and whose content has not been expired yet.
	ListRetentionExpired(ctx context.Context, tenantRef string, now time.Time, limit int) ([]Handle, error)
}

// Record is one normalized business record of the staged evidence envelope.
type Record = map[string]any

// ContentRequest addresses the private source plane. SourceRef comes from the
// registry binding, never from a caller.
type ContentRequest struct {
	TenantRef string
	SourceRef string
	DataClass string
	Fields    []string
	// MaxBytes is the staging bound on the NORMALIZED content. A source MUST
	// enforce it — stop fetching and return ErrContentTooLarge instead of
	// materializing an over-limit result (the service re-checks post-hoc as a
	// backstop against misbehaving sources, but by then the bytes exist).
	MaxBytes int
}

// ContentSource fetches business records from the PRIVATE source plane. The
// production implementation is the connector runtime (later GA tasks); tests
// and harnesses use MemoryContentSource.
type ContentSource interface {
	FetchEvidence(ctx context.Context, req ContentRequest) ([]Record, error)
}

// KeyMaterial is one symmetric content-encryption key with its opaque
// reference. Only the reference is ever persisted.
type KeyMaterial struct {
	Ref string
	Key []byte
}

// KeyProvider is the narrow key port of the staging encryptor. The Task 3
// secret-provider protocol is connector-credential scoped (operation-scoped
// secret handles), so evidence content keys use this dedicated port; a
// deployment adapts its KMS behind it.
type KeyProvider interface {
	// ContentKey returns the CURRENT sealing key of a tenant.
	ContentKey(ctx context.Context, tenantRef string) (KeyMaterial, error)
	// KeyByRef resolves a previously used key by its persisted reference.
	KeyByRef(ctx context.Context, tenantRef, keyRef string) (KeyMaterial, error)
}

// StaticKeyProvider is the fixed-key provider used by unit tests and local
// harnesses. Never configure it with production key material.
type StaticKeyProvider struct {
	Material KeyMaterial
}

func (p StaticKeyProvider) ContentKey(_ context.Context, _ string) (KeyMaterial, error) {
	if p.Material.Ref == "" || len(p.Material.Key) == 0 {
		return KeyMaterial{}, ErrUnavailable
	}
	return p.Material, nil
}

func (p StaticKeyProvider) KeyByRef(_ context.Context, _ string, keyRef string) (KeyMaterial, error) {
	if keyRef != p.Material.Ref || len(p.Material.Key) == 0 {
		return KeyMaterial{}, ErrUnavailable
	}
	return p.Material, nil
}

// AuditEvent is one authorization-lineage append. Details carry ONLY refs,
// hashes, versions and coded reasons — never content, never source topology.
type AuditEvent struct {
	TenantRef    string
	PrincipalRef string
	Action       string
	ResourceType string
	ResourceID   string
	TraceID      string
	Details      map[string]any
}

// AuditSink appends authorization lineage. Locate REQUIRES a successful
// lineage append (fail closed); read denials record best-effort.
type AuditSink interface {
	AppendEvidenceAudit(ctx context.Context, event AuditEvent) (string, error)
}

// CapabilityDecider is the neutral capability policy port, satisfied by
// *policy.CapabilityEvaluator (GA Task 0B). The evidence plane never builds a
// parallel authorization path.
type CapabilityDecider interface {
	Evaluate(ctx context.Context, req policy.CapabilityRequest) (policy.PermissionDecision, error)
}

func canonical(value string) bool { return value != "" && strings.TrimSpace(value) == value }

// hasControlBytes reports whether s contains any ASCII control byte; such
// values are rejected before persistence or logging (injection hazard).
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func randomOpaqueID(prefix string) string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw)
}

// MemoryStore is the in-memory Store used by unit tests and harnesses.
type MemoryStore struct {
	mu       sync.RWMutex
	bindings map[string]SourceBinding
	handles  map[string]Handle
	events   map[string][]HandleEvent
	eventN   int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		bindings: map[string]SourceBinding{},
		handles:  map[string]Handle{},
		events:   map[string][]HandleEvent{},
	}
}

func bindingKey(tenantRef, dataClass string) string { return tenantRef + "\x00" + dataClass }

func handleKey(tenantRef, evidenceRef string) string { return tenantRef + "\x00" + evidenceRef }

// cloneHandle deep-copies the one reference field so store snapshots stay
// immutable (SourceBinding is all value fields and copies by assignment).
func cloneHandle(h Handle) Handle {
	h.Lineage = append([]string(nil), h.Lineage...)
	return h
}

func (s *MemoryStore) UpsertSourceBinding(_ context.Context, binding SourceBinding) (SourceBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(binding.TenantRef, binding.DataClass)
	if existing, ok := s.bindings[key]; ok {
		binding.ID = existing.ID
		binding.CreatedAt = existing.CreatedAt
		// source_version is MONOTONIC: an upsert never lowers it, and reviving
		// a tombstoned binding always bumps PAST the tombstoned version, so
		// handles denied by source deletion can never silently become readable
		// again (mirrors the PostgreSQL upsert).
		floor := existing.SourceVersion
		if existing.Deleted {
			floor++
		}
		if binding.SourceVersion < floor {
			binding.SourceVersion = floor
		}
	}
	binding.Deleted = false
	s.bindings[key] = binding
	return binding, nil
}

func (s *MemoryStore) GetSourceBinding(_ context.Context, tenantRef, dataClass string) (SourceBinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	binding, ok := s.bindings[bindingKey(tenantRef, dataClass)]
	if !ok {
		return SourceBinding{}, ErrNotFound
	}
	return binding, nil
}

func (s *MemoryStore) BumpSourceVersion(_ context.Context, tenantRef, dataClass string, now time.Time) (SourceBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(tenantRef, dataClass)
	binding, ok := s.bindings[key]
	if !ok {
		return SourceBinding{}, ErrNotFound
	}
	binding.SourceVersion++
	binding.UpdatedAt = now
	s.bindings[key] = binding
	return binding, nil
}

func (s *MemoryStore) MarkSourceDeleted(_ context.Context, tenantRef, dataClass string, now time.Time) (SourceBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bindingKey(tenantRef, dataClass)
	binding, ok := s.bindings[key]
	if !ok {
		return SourceBinding{}, ErrNotFound
	}
	binding.Deleted = true
	binding.UpdatedAt = now
	s.bindings[key] = binding
	return binding, nil
}

func (s *MemoryStore) CreateHandle(_ context.Context, handle Handle) (Handle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := handleKey(handle.TenantRef, handle.EvidenceRef)
	if _, exists := s.handles[key]; exists {
		return Handle{}, ErrUnavailable
	}
	s.handles[key] = cloneHandle(handle)
	return cloneHandle(handle), nil
}

func (s *MemoryStore) GetHandle(_ context.Context, tenantRef, evidenceRef string) (Handle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	handle, ok := s.handles[handleKey(tenantRef, evidenceRef)]
	if !ok {
		return Handle{}, ErrNotFound
	}
	return cloneHandle(handle), nil
}

func (s *MemoryStore) AppendHandleEvent(_ context.Context, event HandleEvent) (HandleEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !event.Kind.valid() {
		return HandleEvent{}, ErrUnavailable
	}
	key := handleKey(event.TenantRef, event.EvidenceRef)
	if _, ok := s.handles[key]; !ok {
		return HandleEvent{}, ErrNotFound
	}
	s.eventN++
	event.Seq = s.eventN
	s.events[key] = append(s.events[key], event)
	return event, nil
}

func (s *MemoryStore) ListHandleEvents(_ context.Context, tenantRef, evidenceRef string) ([]HandleEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	log := s.events[handleKey(tenantRef, evidenceRef)]
	return append([]HandleEvent(nil), log...), nil
}

func (s *MemoryStore) ListRetentionExpired(_ context.Context, tenantRef string, now time.Time, limit int) ([]Handle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Handle
	for key, handle := range s.handles {
		if handle.TenantRef != tenantRef || handle.RetentionExpiresAt.IsZero() || handle.RetentionExpiresAt.After(now) {
			continue
		}
		expired := false
		for _, event := range s.events[key] {
			if event.Kind == HandleEventContentExpired {
				expired = true
				break
			}
		}
		if !expired {
			out = append(out, cloneHandle(handle))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].RetentionExpiresAt.Equal(out[j].RetentionExpiresAt) {
			return out[i].RetentionExpiresAt.Before(out[j].RetentionExpiresAt)
		}
		return out[i].EvidenceRef < out[j].EvidenceRef
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Handles returns every handle of a tenant (test observability only).
func (s *MemoryStore) Handles(tenantRef string) []Handle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Handle
	for _, handle := range s.handles {
		if handle.TenantRef == tenantRef {
			out = append(out, cloneHandle(handle))
		}
	}
	return out
}

// MemoryContentSource is the in-memory ContentSource used by unit tests and
// harnesses; it is keyed by the PRIVATE source reference, proving resolution
// goes through the registry binding.
type MemoryContentSource struct {
	mu      sync.RWMutex
	records map[string][]Record
}

func NewMemoryContentSource() *MemoryContentSource {
	return &MemoryContentSource{records: map[string][]Record{}}
}

// Seed installs the records served for a source reference.
func (s *MemoryContentSource) Seed(sourceRef string, records []Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := make([]Record, 0, len(records))
	for _, record := range records {
		copied := Record{}
		for key, value := range record {
			copied[key] = value
		}
		cloned = append(cloned, copied)
	}
	s.records[sourceRef] = cloned
}

func (s *MemoryContentSource) FetchEvidence(_ context.Context, req ContentRequest) ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records, ok := s.records[req.SourceRef]
	if !ok {
		return nil, ErrUnavailable
	}
	out := make([]Record, 0, len(records))
	total := 0
	for _, record := range records {
		copied := Record{}
		for key, value := range record {
			copied[key] = value
		}
		// Honor the staging bound the way a well-behaved source must: stop
		// accumulating and fail explicitly instead of materializing an
		// over-limit result.
		if req.MaxBytes > 0 {
			encoded, err := json.Marshal(copied)
			if err != nil {
				return nil, err
			}
			total += len(encoded) + 1
			if total > req.MaxBytes {
				return nil, ErrContentTooLarge
			}
		}
		out = append(out, copied)
	}
	return out, nil
}
