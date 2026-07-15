// Package approvaltransport is the GA Task 0E approval TRANSMISSION plane.
//
// Locked product boundary: AgentAtlas (or the customer's OA/BPM approval
// authority) decides business intent, risk and the approval plan — WHO
// approves, in WHAT order, under WHICH policy. AgentNexus transmits the
// caller's signed plan UNCHANGED to the configured channel, persists the
// correlation and delivery attempts, validates the evidence the authority
// returns (exact operation binding, provenance, expiry, revocation, replay)
// and exposes status for diagnostics.
//
// AgentNexus therefore has NO approver vocabulary here: no reviewer ids, no
// organization walking, no queue routing and no domain risk classification.
// The permanent boundary guard (TestNoApprovalPolicyOwnership) rejects that
// vocabulary from every production source.
//
// Grant seam (Task 0F): this package only STORES validated evidence. Nothing
// in it creates, unlocks or consumes a grant — the awaiting_approval->granted
// Action transition and evidence consumption (including the one-grant-per-
// evidence replay gate backed by the consumed_at column) are Task 0F.
package approvaltransport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
)

// Errors of the transmission plane. Callers fail closed on ErrUnavailable.
var (
	// ErrInvalidInput marks malformed input (principal, request, handle or
	// reason).
	ErrInvalidInput = errors.New("invalid approval transmission input")
	// ErrUnavailable marks a persistence or audit outage; callers fail closed.
	ErrUnavailable = errors.New("approval transmission unavailable")
	// ErrNotFound marks a transmission that does not exist under the caller's
	// tenant.
	ErrNotFound = errors.New("approval transmission not found")
	// ErrPlanConflict marks an attempt to rebind an existing plan_ref to a
	// different operation or plan digest.
	ErrPlanConflict = errors.New("approval plan conflict")
	// ErrCallerUntrusted rejects transmission attempts by callers whose trust
	// context cannot reach the approval plane: untrusted Agents always, and
	// certified third parties without a wired certified-decision-provider
	// verification (the nil seam is never a pass-stub).
	ErrCallerUntrusted = errors.New("approval transmission requires a trusted decision provider")
	// ErrEvidenceRejected marks evidence that fails validation: canonical
	// shape, exact Action/parameter binding, plan digest or authority
	// provenance.
	ErrEvidenceRejected = errors.New("approval evidence rejected")
	// ErrEvidenceReplay marks a replayed approval_ref (mutated content, a
	// second decision for the same plan, or reuse against another plan).
	ErrEvidenceReplay = errors.New("approval evidence replayed")
	// ErrEvidenceExpired marks evidence arriving after the transmission
	// expiry window.
	ErrEvidenceExpired = errors.New("approval evidence expired")
	// ErrTransmissionRevoked marks operations against a revoked transmission.
	ErrTransmissionRevoked = errors.New("approval transmission revoked")
	// ErrEvidenceConsumed marks a second attempt to consume a validated evidence
	// record (the consumed_at one-shot replay gate). Task 0F surfaces this as a
	// double-consumption rejection.
	ErrEvidenceConsumed = errors.New("approval evidence already consumed")
)

// TransmissionStatus is the frozen transport lifecycle vocabulary. It carries
// TRANSPORT facts only — deliberately no grant state (grants are Task 0F).
type TransmissionStatus string

const (
	// StatusPending: correlation accepted; no delivery confirmed yet.
	StatusPending TransmissionStatus = "pending"
	// StatusDelivered: the configured channel accepted the plan.
	StatusDelivered TransmissionStatus = "delivered"
	// StatusEvidenceRecorded: validated evidence from the approval authority
	// is stored for Task 0F to consume.
	StatusEvidenceRecorded TransmissionStatus = "evidence_recorded"
	// StatusRevoked: the transmission was revoked; terminal.
	StatusRevoked TransmissionStatus = "revoked"
)

// statusRank orders the monotonic lifecycle: a stored status never regresses
// (out-of-order delivery confirmations cannot demote recorded evidence) and
// revocation is terminal.
func statusRank(status TransmissionStatus) int {
	switch status {
	case StatusPending:
		return 1
	case StatusDelivered:
		return 2
	case StatusEvidenceRecorded:
		return 3
	case StatusRevoked:
		return 4
	}
	return 0
}

// DeliveryOutcome is the per-attempt channel outcome vocabulary.
type DeliveryOutcome string

const (
	DeliveryDelivered DeliveryOutcome = "delivered"
	DeliveryFailed    DeliveryOutcome = "failed"
)

// Transmission is the persisted correlation of one transmitted approval plan:
// the exact operation binding, the transport lifecycle and — once validated —
// the authority's decision. It carries no approver identity by design.
type Transmission struct {
	TenantRef           string
	PlanRef             string
	PlanHash            string
	Authority           string
	BusinessContextRef  string
	Capability          string
	ParameterHash       string
	Purpose             string
	Status              TransmissionStatus
	ExpiresAt           time.Time
	DeliveryAttempts    int
	LastDeliveryOutcome DeliveryOutcome
	LastDeliveryReason  string
	Decision            runtime.ApprovalDecision
	DecidedAt           time.Time
	RevokedAt           time.Time
	RevocationReason    string
	AuditRefID          string
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// sameBinding reports whether a re-transmitted request carries the exact
// binding already persisted for the plan_ref.
func (t Transmission) sameBinding(other Transmission) bool {
	return t.PlanHash == other.PlanHash && t.Authority == other.Authority &&
		t.BusinessContextRef == other.BusinessContextRef && t.Capability == other.Capability &&
		t.ParameterHash == other.ParameterHash && t.Purpose == other.Purpose &&
		t.ExpiresAt.Equal(other.ExpiresAt)
}

// EvidenceRecord is the single validated decision of a transmitted plan,
// stored for Task 0F to consume. ConsumedAt is the 0F replay gate: this
// package never sets it.
type EvidenceRecord struct {
	TenantRef    string
	Evidence     runtime.ApprovalEvidence
	EvidenceHash string
	AuditRefID   string
	RecordedAt   time.Time
	ConsumedAt   time.Time
}

// ConsumedEvidence is the exact-operation binding returned when Task 0F
// consumes a validated approval evidence record one-shot. It carries only the
// decision binding the action lifecycle needs; no attestation value or approver
// identity.
type ConsumedEvidence struct {
	ApprovalRef   string
	PlanRef       string
	Capability    string
	ParameterHash string
	Decision      runtime.ApprovalDecision
}

// CanonicalEvidenceHash is the deterministic content digest used for
// duplicate-delivery vs replay discrimination: identical resubmissions are
// idempotent, mutated ones are rejected.
func CanonicalEvidenceHash(evidence runtime.ApprovalEvidence) string {
	evidence.DecidedAt = evidence.DecidedAt.UTC()
	payload, err := json.Marshal(evidence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// AuditEvent is the narrow audit port payload. Actions are the internal
// approval-transmission lineage vocabulary: approval.plan.transmit,
// approval.evidence.record, approval.transmission.revoke.
type AuditEvent struct {
	TenantRef    string
	PrincipalRef string
	Action       string
	PlanRef      string
	Decision     string
	Details      map[string]any
}

// AuditSink appends approval-transmission lineage. Appends are MANDATORY for
// transmit acceptance, evidence recording and revocation: a failed append
// fails the operation closed (Task 0G chains the events).
type AuditSink interface {
	AppendApprovalAudit(ctx context.Context, event AuditEvent) (string, error)
}

// DecisionProviderVerifier is the narrow 0F seam that proves a certified
// third-party caller is backed by a certified Policy Decision Provider
// (agenttrust certification fact). nil wiring is NEVER a pass-stub: without
// the verifier a certified third party cannot transmit at all — there is no
// local check that could establish provider certification.
type DecisionProviderVerifier interface {
	VerifyDecisionProvider(ctx context.Context, tenantRef string, principal runtime.PrincipalContext, plan runtime.ApprovalPlanRef) error
}

// AttestationVerifier is the narrow 0F/0G seam that cryptographically
// verifies evidence attestations against registered authority keys. nil
// wiring means LOCAL CHECKS ONLY (canonical shape, exact binding, provenance,
// expiry, revocation, replay) — a wired verifier only ever ADDS verification
// and never weakens the local checks.
type AttestationVerifier interface {
	VerifyEvidenceAttestation(ctx context.Context, tenantRef string, evidence runtime.ApprovalEvidence) error
}

// Store is the persistence port. The store OWNS the lifecycle invariants:
// one correlation per (tenant, plan_ref), monotonic status, one validated
// evidence record per plan, a globally unique approval_ref per tenant and an
// append-only delivery/revocation history.
type Store interface {
	// CreateTransmission persists a new correlation row. It reports
	// created=false when the row already existed (callers disambiguate
	// binding equality themselves).
	CreateTransmission(ctx context.Context, transmission Transmission) (Transmission, bool, error)
	GetTransmission(ctx context.Context, tenantRef, planRef string) (Transmission, error)
	// RecordDeliveryAttempt appends one attempt and, on a delivered outcome,
	// advances pending->delivered. It never regresses a later status.
	RecordDeliveryAttempt(ctx context.Context, tenantRef, planRef string, outcome DeliveryOutcome, reason string, at time.Time) (Transmission, error)
	// RecordEvidence stores the single validated evidence record of a plan
	// and advances the status to evidence_recorded. It reports created=false
	// for an existing identical record; a conflicting record fails
	// ErrEvidenceReplay; a revoked transmission fails ErrTransmissionRevoked.
	RecordEvidence(ctx context.Context, record EvidenceRecord) (EvidenceRecord, bool, error)
	GetEvidence(ctx context.Context, tenantRef, planRef string) (EvidenceRecord, error)
	// ConsumeEvidence stamps consumed_at on the validated evidence record for
	// (tenant, plan_ref) EXACTLY ONCE and returns the exact operation binding it
	// approved (the GA Task 0F grant-consumption seam). A second consume fails
	// ErrEvidenceConsumed; an absent record fails ErrNotFound; a revoked
	// transmission fails ErrTransmissionRevoked. 0E never sets consumed_at.
	ConsumeEvidence(ctx context.Context, tenantRef, planRef string, at time.Time) (ConsumedEvidence, error)
	// Revoke marks the transmission revoked (terminal, idempotent) and
	// appends the revocation record.
	Revoke(ctx context.Context, tenantRef, planRef, reason, revocationID string, at time.Time) (Transmission, error)
}

func canonical(value string) bool { return value != "" && strings.TrimSpace(value) == value }

// hasControlBytes rejects ASCII control bytes in persisted reasons (NUL
// hazard, log injection).
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// MemoryStore is the in-memory Store used by unit tests and local harnesses.
type MemoryStore struct {
	mu            sync.Mutex
	transmissions map[string]Transmission
	attempts      map[string][]DeliveryOutcome
	evidence      map[string]EvidenceRecord // keyed by tenant/plan
	evidenceRefs  map[string]string         // tenant/approval_ref -> tenant/plan key
	revocations   map[string]string         // tenant/plan -> revocation id
}

// NewMemoryStore builds an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		transmissions: map[string]Transmission{},
		attempts:      map[string][]DeliveryOutcome{},
		evidence:      map[string]EvidenceRecord{},
		evidenceRefs:  map[string]string{},
		revocations:   map[string]string{},
	}
}

// storeKey joins tenant and ref with a NUL byte for IN-PROCESS Go map keys
// ONLY. The NUL joiner is legal in Go strings but must NEVER cross the SQL
// boundary: PostgreSQL rejects NUL bytes in text parameters, so the durable
// store passes tenant and plan as SEPARATE query parameters (see
// lockTransmission and TestApprovalTransportSQLParametersCarryNoNULJoiner).
func storeKey(tenantRef, ref string) string { return tenantRef + "\x00" + ref }

func (s *MemoryStore) CreateTransmission(_ context.Context, transmission Transmission) (Transmission, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(transmission.TenantRef, transmission.PlanRef)
	if existing, ok := s.transmissions[key]; ok {
		return existing, false, nil
	}
	s.transmissions[key] = transmission
	return transmission, true, nil
}

func (s *MemoryStore) GetTransmission(_ context.Context, tenantRef, planRef string) (Transmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	transmission, ok := s.transmissions[storeKey(tenantRef, planRef)]
	if !ok {
		return Transmission{}, ErrNotFound
	}
	return transmission, nil
}

func (s *MemoryStore) RecordDeliveryAttempt(_ context.Context, tenantRef, planRef string, outcome DeliveryOutcome, reason string, at time.Time) (Transmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(tenantRef, planRef)
	transmission, ok := s.transmissions[key]
	if !ok {
		return Transmission{}, ErrNotFound
	}
	s.attempts[key] = append(s.attempts[key], outcome)
	transmission.DeliveryAttempts = len(s.attempts[key])
	transmission.LastDeliveryOutcome = outcome
	transmission.LastDeliveryReason = reason
	if outcome == DeliveryDelivered && statusRank(StatusDelivered) > statusRank(transmission.Status) {
		transmission.Status = StatusDelivered
	}
	transmission.UpdatedAt = at
	s.transmissions[key] = transmission
	return transmission, nil
}

func (s *MemoryStore) RecordEvidence(_ context.Context, record EvidenceRecord) (EvidenceRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	planKey := storeKey(record.TenantRef, record.Evidence.PlanRef)
	transmission, ok := s.transmissions[planKey]
	if !ok {
		return EvidenceRecord{}, false, ErrNotFound
	}
	if transmission.Status == StatusRevoked {
		return EvidenceRecord{}, false, ErrTransmissionRevoked
	}
	refKey := storeKey(record.TenantRef, record.Evidence.ApprovalRef)
	if boundPlan, exists := s.evidenceRefs[refKey]; exists {
		existing := s.evidence[boundPlan]
		if boundPlan == planKey && existing.EvidenceHash == record.EvidenceHash {
			return existing, false, nil
		}
		return EvidenceRecord{}, false, ErrEvidenceReplay
	}
	if _, exists := s.evidence[planKey]; exists {
		// A different approval_ref for an already-decided plan: one plan
		// carries exactly one validated decision.
		return EvidenceRecord{}, false, ErrEvidenceReplay
	}
	s.evidence[planKey] = record
	s.evidenceRefs[refKey] = planKey
	if statusRank(StatusEvidenceRecorded) > statusRank(transmission.Status) {
		transmission.Status = StatusEvidenceRecorded
	}
	transmission.Decision = record.Evidence.Decision
	transmission.DecidedAt = record.Evidence.DecidedAt
	transmission.UpdatedAt = record.RecordedAt
	s.transmissions[planKey] = transmission
	return record, true, nil
}

func (s *MemoryStore) GetEvidence(_ context.Context, tenantRef, planRef string) (EvidenceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.evidence[storeKey(tenantRef, planRef)]
	if !ok {
		return EvidenceRecord{}, ErrNotFound
	}
	return record, nil
}

func (s *MemoryStore) ConsumeEvidence(_ context.Context, tenantRef, planRef string, at time.Time) (ConsumedEvidence, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	planKey := storeKey(tenantRef, planRef)
	transmission, ok := s.transmissions[planKey]
	if ok && transmission.Status == StatusRevoked {
		return ConsumedEvidence{}, ErrTransmissionRevoked
	}
	record, ok := s.evidence[planKey]
	if !ok {
		return ConsumedEvidence{}, ErrNotFound
	}
	if !record.ConsumedAt.IsZero() {
		return ConsumedEvidence{}, ErrEvidenceConsumed
	}
	record.ConsumedAt = at.UTC()
	s.evidence[planKey] = record
	return ConsumedEvidence{
		ApprovalRef:   record.Evidence.ApprovalRef,
		PlanRef:       record.Evidence.PlanRef,
		Capability:    record.Evidence.Capability,
		ParameterHash: record.Evidence.ParameterHash,
		Decision:      record.Evidence.Decision,
	}, nil
}

func (s *MemoryStore) Revoke(_ context.Context, tenantRef, planRef, reason, revocationID string, at time.Time) (Transmission, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(tenantRef, planRef)
	transmission, ok := s.transmissions[key]
	if !ok {
		return Transmission{}, ErrNotFound
	}
	if transmission.Status == StatusRevoked {
		return transmission, nil
	}
	s.revocations[key] = revocationID
	transmission.Status = StatusRevoked
	transmission.RevokedAt = at
	transmission.RevocationReason = reason
	transmission.UpdatedAt = at
	s.transmissions[key] = transmission
	return transmission, nil
}

// Transmissions returns every stored transmission ordered by plan_ref (test
// observability).
func (s *MemoryStore) Transmissions() []Transmission {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Transmission, 0, len(s.transmissions))
	for _, transmission := range s.transmissions {
		out = append(out, transmission)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PlanRef < out[j].PlanRef })
	return out
}

// MemoryAuditSink records approval audit events in memory (unit tests and
// local harnesses).
type MemoryAuditSink struct {
	mu         sync.Mutex
	events     []AuditEvent
	fail       error
	failAction string
	failErr    error
	minted     int
}

// NewMemoryAuditSink builds an empty in-memory audit sink.
func NewMemoryAuditSink() *MemoryAuditSink { return &MemoryAuditSink{} }

// SetFailure makes every subsequent append fail with err (nil clears).
func (s *MemoryAuditSink) SetFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

// SetFailureForAction makes appends of exactly one action fail with err
// (nil err clears) — used to exercise the post-persist acceptance-marker
// failure path.
func (s *MemoryAuditSink) SetFailureForAction(action string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAction, s.failErr = action, err
}

func (s *MemoryAuditSink) AppendApprovalAudit(_ context.Context, event AuditEvent) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return "", s.fail
	}
	if s.failErr != nil && event.Action == s.failAction {
		return "", s.failErr
	}
	s.minted++
	s.events = append(s.events, event)
	return "approvalaudit_" + itoaAudit(s.minted), nil
}

// Events returns a copy of the appended events.
func (s *MemoryAuditSink) Events() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEvent(nil), s.events...)
}

func itoaAudit(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
