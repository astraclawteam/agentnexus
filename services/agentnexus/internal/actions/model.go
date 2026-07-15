// Package actions is the GA Task 0F durable controlled-execution plane: the
// one logical Action state machine, the one-use grant consumption, the
// transactional outbox/inbox and the reconcile/compensate paths.
//
// Locked authority boundary (frozen by contract v1.0.0/v1.3.0): an Action's
// `succeeded` status means the declared TECHNICAL execution succeeded — never
// that an AgentAtlas WorkCase or business goal was achieved. No transition,
// stored field, audit event, receipt or API response in this package asserts a
// business Outcome, sets outcome/goal_achieved, or writes an AgentAtlas graph
// edge (the public_contract_parity_test bans those names). Post-action
// verification of a declared postcondition happens SEPARATELY through the Task
// 0D evidence service, which mints the signed ObservationReceipt; this package
// only triggers the exact declared VerificationNeeds and records the receipt
// refs.
//
// Grant boundary: the Action one-use grant is the SDK runtime.StepGrant shape
// (capability + parameter_hash + business_context, one-use), minted and
// consumed transactionally with the Action. Its SHAPE and one-use rules live
// in internal/tickets (tickets.MintActionGrant / tickets.ConsumeActionGrant);
// this package owns the durable persistence and the atomic transitions. The
// legacy resource-scoped tickets.StepGrant (dream_evidence) is a DIFFERENT
// mechanism and is untouched.
package actions

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

// Errors of the durable action plane. Callers fail closed on ErrUnavailable.
var (
	// ErrInvalidInput marks malformed input (principal, request or handle).
	ErrInvalidInput = errors.New("invalid action input")
	// ErrUnavailable marks a persistence or audit outage; callers fail closed.
	ErrUnavailable = errors.New("action plane unavailable")
	// ErrNotFound marks an action that does not exist under the caller's tenant.
	ErrNotFound = errors.New("action not found")
	// ErrIdempotencyConflict marks a reused idempotency key that binds a
	// DIFFERENT operation (capability / parameter_hash / business_context): one
	// logical Action per (tenant, idempotency_key), never a second side effect.
	ErrIdempotencyConflict = errors.New("idempotency key bound to a different operation")
	// ErrForbiddenTransition rejects a status transition that is not an allowed
	// edge of the frozen state machine.
	ErrForbiddenTransition = errors.New("forbidden action transition")
	// ErrCallerUntrusted rejects a request whose verified trust context cannot
	// reach a side effect: untrusted callers always, and certified third parties
	// without a wired certified-decision-provider verification (the nil seam is
	// never a pass-stub).
	ErrCallerUntrusted = errors.New("action requires a trusted decision provider")
	// ErrApprovalRequired marks a grant attempt on an action still awaiting the
	// approval authority's evidence.
	ErrApprovalRequired = errors.New("action awaiting approval evidence")
	// ErrEvidenceRejected marks approval evidence that does not bind the exact
	// operation of the action, or evidence for a revoked/absent transmission.
	ErrEvidenceRejected = errors.New("approval evidence rejected for this action")
	// ErrEvidenceConsumed marks a second attempt to consume the same one-shot
	// approval evidence (the consumed_at replay gate) or the one-use grant.
	ErrEvidenceConsumed = errors.New("approval evidence or grant already consumed")
	// ErrReceiptRejected marks an execution receipt that does not bind the exact
	// action (action_ref / parameter_hash / capability), whose ReceiptSchema
	// does not match the request's ExpectedReceiptSchema, or that fails the
	// wired ReceiptVerifier.
	ErrReceiptRejected = errors.New("action receipt rejected")
	// ErrBlindRetryForbidden marks an attempt to re-dispatch an action whose
	// side effect may already have executed (result_unknown): the only safe path
	// is reconciliation, never a blind retry.
	ErrBlindRetryForbidden = errors.New("blind re-dispatch is forbidden; reconcile instead")
	// ErrCompensationUndeclared marks a compensation trigger for an action that
	// declared no compensation reference.
	ErrCompensationUndeclared = errors.New("action declared no compensation reference")
	// ErrNotImplemented is the RED sentinel: it marks an action-plane operation
	// whose behavior is not yet implemented. GREEN removes every use.
	ErrNotImplemented = errors.New("action plane operation not implemented")
)

// Frozen action statuses re-exported from the SDK for local readability.
const (
	StatusRequested        = runtime.StatusRequested
	StatusAwaitingApproval = runtime.StatusAwaitingApproval
	StatusGranted          = runtime.StatusGranted
	StatusDispatched       = runtime.StatusDispatched
	StatusExecuting        = runtime.StatusExecuting
	StatusSucceeded        = runtime.StatusSucceeded
	StatusFailed           = runtime.StatusFailed
	StatusResultUnknown    = runtime.StatusResultUnknown
	StatusReconciling      = runtime.StatusReconciling
	StatusCompensating     = runtime.StatusCompensating
	StatusHumanTakeover    = runtime.StatusHumanTakeover
)

// maxActionGrantTTL caps the minted one-use grant lifetime (mirrors
// tickets.MaxStepGrantTTL): a grant is short-lived by contract.
const maxActionGrantTTL = tickets.MaxActionGrantTTL

// Action is the durable record of one requested side effect. The binding
// columns (tenant_ref, action_ref, capability, parameter_hash,
// business_context_ref, idempotency_key, created_at) are immutable; status only
// advances along the allowed edges.
type Action struct {
	TenantRef             string
	ActionRef             string
	Status                runtime.ActionStatus
	BusinessContextRef    string
	Capability            string
	ParameterHash         string
	IdempotencyKey        string
	RiskAuthority         string
	RiskLevel             runtime.RiskLevel
	ApprovalPlanRef       string
	GrantRef              string
	ApprovalEvidenceRef   string
	ReceiptRef            string
	CompensationRef       string
	CompensationOf        string
	ExpectedReceiptSchema string
	Postconditions        []runtime.PostconditionSpec
	VerificationNeeds     []runtime.VerificationNeed
	ExpiresAt             time.Time
	AuditRefID            string
	FailureReason         string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// Runtime projects the durable Action onto the frozen SDK view returned on the
// public /v1/runtime/act surface.
func (a Action) Runtime() runtime.Action {
	return runtime.Action{
		ActionRef:           a.ActionRef,
		Status:              a.Status,
		BusinessContextRef:  a.BusinessContextRef,
		Capability:          a.Capability,
		ParameterHash:       a.ParameterHash,
		GrantRef:            a.GrantRef,
		ApprovalEvidenceRef: a.ApprovalEvidenceRef,
		ReceiptRef:          a.ReceiptRef,
		UpdatedAt:           a.UpdatedAt,
	}
}

// hasPostcondition reports whether id is a declared postcondition of the action.
func (a Action) hasPostcondition(id string) bool {
	for _, p := range a.Postconditions {
		if p.PostconditionID == id {
			return true
		}
	}
	return false
}

// verificationNeed returns the declared need with needID, if any.
func (a Action) verificationNeed(needID string) (runtime.VerificationNeed, bool) {
	for _, n := range a.VerificationNeeds {
		if n.NeedID == needID {
			return n, true
		}
	}
	return runtime.VerificationNeed{}, false
}

// Grant is the durable one-use grant row bound to exactly one Action.
type Grant struct {
	TenantRef          string
	GrantRef           string
	ActionRef          string
	BusinessContextRef string
	Capability         string
	ParameterHash      string
	OneUse             bool
	IssuedAt           time.Time
	ExpiresAt          time.Time
	ConsumedAt         time.Time
}

// Dispatch is the durable dispatch intent written to the transactional outbox
// atomically with the granted->dispatched transition.
type Dispatch struct {
	TenantRef     string
	DispatchRef   string
	ActionRef     string
	Capability    string
	ParameterHash string
	GrantRef      string
	Kind          DispatchKind
	Published     bool
	Attempts      int
	CreatedAt     time.Time
	PublishedAt   time.Time
}

// DispatchKind separates an original execution dispatch from a compensation
// dispatch (the compensation carries its own new grant and receipts).
type DispatchKind string

const (
	DispatchExecute    DispatchKind = "execute"
	DispatchCompensate DispatchKind = "compensate"
)

// Result is one connector-reported execution result. The result_id is the
// inbox dedup key: a redelivered or duplicate result with the same id is
// applied exactly once.
type Result struct {
	TenantRef string
	ResultID  string
	ActionRef string
	Receipt   runtime.ActionReceipt
}

// RequestInput is the validated ActionRequest plus the verified tenant, ready
// to persist as one logical Action.
type RequestInput struct {
	TenantRef string
	ActionRef string
	Request   runtime.ActionRequest
}

// Store is the durable persistence port. The store OWNS the transition
// invariants: one Action per (tenant, idempotency_key), monotonic status along
// the allowed edges, one grant per Action consumed at most once, an
// append-only outbox and a dedup inbox. Every method is one atomic unit.
type Store interface {
	// PutRequested persists a new logical Action idempotently. It reports
	// created=false and returns the existing Action when (tenant,
	// idempotency_key) already exists; a reused key that binds a different
	// operation fails ErrIdempotencyConflict.
	PutRequested(ctx context.Context, action Action) (Action, bool, error)
	// GetByIdempotencyKey returns the existing Action for (tenant, key), or
	// ErrNotFound. It is the idempotent pre-check before minting a new Action.
	GetByIdempotencyKey(ctx context.Context, tenantRef, idempotencyKey string) (Action, error)
	GetAction(ctx context.Context, tenantRef, actionRef string) (Action, error)
	// Grant advances requested|awaiting_approval -> granted: it persists the
	// one-use grant row and stamps grant_ref/approval_evidence_ref/status in one
	// transaction. The from-state is verified against the allowed edge.
	Grant(ctx context.Context, action Action, grant Grant) (Action, error)
	// Dispatch advances granted -> dispatched: it consumes the one-use grant
	// (consumed_at NULL->NOT-NULL exactly once) AND writes the outbox row in one
	// transaction. A second dispatch fails ErrEvidenceConsumed.
	Dispatch(ctx context.Context, tenantRef, actionRef string, dispatch Dispatch, at time.Time) (Action, error)
	// Transition advances an action along one allowed edge with no side rows
	// (dispatched->executing, executing->result_unknown, result_unknown->
	// reconciling, any->human_takeover, cancellation). reason is persisted for
	// human_takeover/failed.
	Transition(ctx context.Context, tenantRef, actionRef string, from, to runtime.ActionStatus, reason string, at time.Time) (Action, error)
	// IngestResult applies one connector result exactly once: the inbox dedups
	// by result_id, the receipt is persisted and the action advances to the
	// receipt's terminal status. It reports applied=false for a duplicate.
	IngestResult(ctx context.Context, result Result, to runtime.ActionStatus, at time.Time) (Action, bool, error)
	// GetReceipt returns the persisted receipt of an action by receipt_ref.
	GetReceipt(ctx context.Context, tenantRef, receiptRef string) (runtime.ActionReceipt, error)
	// ResultApplied reports whether a connector result_id was already applied
	// (inbox membership). The service consults it to distinguish an idempotent
	// duplicate from an out-of-order receipt BEFORE emitting a completion audit.
	ResultApplied(ctx context.Context, tenantRef, resultID string) (bool, error)
	// PendingDispatches returns unpublished outbox rows for the recovery pump.
	PendingDispatches(ctx context.Context, tenantRef string, limit int) ([]Dispatch, error)
	// MarkDispatchPublished stamps an outbox row published after the pump
	// delivered it to the connector transport.
	MarkDispatchPublished(ctx context.Context, tenantRef, dispatchRef string, at time.Time) error
}

// EvidenceConsumer is the one-shot approval-evidence gate (Task 0E store seam).
// The actions service consumes validated approval evidence EXACTLY once when it
// mints the grant; a second consume is rejected by the consumed_at trigger.
type EvidenceConsumer interface {
	// ConsumeApprovalEvidence stamps consumed_at on the validated evidence
	// record for (tenant, plan_ref) and returns the exact operation binding it
	// approved. A second consume, a revoked/absent record, fail closed.
	ConsumeApprovalEvidence(ctx context.Context, tenantRef, planRef string, at time.Time) (ConsumedEvidence, error)
}

// ConsumedEvidence is the exact-operation binding of a consumed approval
// evidence record: the actions service checks it against the Action before
// minting the grant.
type ConsumedEvidence struct {
	ApprovalRef   string
	PlanRef       string
	Capability    string
	ParameterHash string
	Decision      runtime.ApprovalDecision
}

// DecisionProviderVerifier is the certified-decision-provider trust seam. It is
// the SAME contract as approvaltransport.DecisionProviderVerifier: nil wiring is
// NEVER a pass-stub — without it a certified third party cannot reach a side
// effect. It is wired ONCE in the composition root to both planes.
type DecisionProviderVerifier interface {
	VerifyDecisionProvider(ctx context.Context, tenantRef string, principal runtime.PrincipalContext, capability, parameterHash string) error
}

// ReceiptVerifier is the GA Task 0G seam: when wired it AUTHORITATIVELY verifies
// the ActionReceipt signature against registered connector keys. Nil until 0G ⇒
// LOCAL STRUCTURAL verification only (exact action/parameter/capability binding,
// ReceiptSchema == ExpectedReceiptSchema, result_hash match). A nil port never
// silently passes a wired rejection and never weakens the local checks; a wired
// verifier only ever ADDS the signature check. "Only a verified signed
// ActionReceipt completes an Action" flows through this seam.
type ReceiptVerifier interface {
	VerifyReceipt(ctx context.Context, tenantRef string, receipt runtime.ActionReceipt) error
}

// AuditEvent is the narrow audit port payload for one action transition. Task
// 0G chains and signs these events; 0F produces the unsigned chained links with
// status_from/status_to.
type AuditEvent struct {
	TenantRef    string
	PrincipalRef string
	Action       string
	ActionRef    string
	StatusFrom   runtime.ActionStatus
	StatusTo     runtime.ActionStatus
	Details      map[string]any
	// GA Task 0G first-class binding refs (recoverable, individually signed):
	// the exact operation, the grant, the approval evidence, the receipt, the
	// risk authority and the verified Agent-client/release/org-snapshot context.
	Capability          string
	ParameterHash       string
	GrantRef            string
	ApprovalEvidenceRef string
	ReceiptRef          string
	RiskAuthority       string
	AgentClientRef      string
	AgentReleaseRef     string
	OrgSnapshotRef      string
}

// AuditSink appends action-transition lineage. Appends are MANDATORY: a failed
// append fails the transition closed.
type AuditSink interface {
	AppendActionAudit(ctx context.Context, event AuditEvent) (string, error)
}

// storeKey joins tenant and ref with a NUL byte for IN-PROCESS Go map keys
// ONLY. PostgreSQL rejects NUL bytes in text parameters, so the durable store
// passes tenant and ref as SEPARATE query parameters (two-int advisory lock);
// TestActionSQLParametersCarryNoNULJoiner keeps the NUL out of the SQL surface.
func storeKey(tenantRef, ref string) string { return tenantRef + "\x00" + ref }

// MemoryStore is the in-memory Store used by unit tests and local harnesses.
// The durability / crash-replay / reconcile / redelivery tests use the
// PostgresStore against the real database instead.
type MemoryStore struct {
	mu         sync.Mutex
	actions    map[string]Action                // tenant/action_ref
	byIdem     map[string]string                // tenant/idempotency_key -> action_ref
	grants     map[string]Grant                 // tenant/action_ref
	dispatches map[string]Dispatch              // tenant/dispatch_ref
	inbox      map[string]bool                  // tenant/result_id
	receipts   map[string]runtime.ActionReceipt // tenant/receipt_ref
}

// NewMemoryStore builds an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		actions:    map[string]Action{},
		byIdem:     map[string]string{},
		grants:     map[string]Grant{},
		dispatches: map[string]Dispatch{},
		inbox:      map[string]bool{},
		receipts:   map[string]runtime.ActionReceipt{},
	}
}

func (s *MemoryStore) PutRequested(_ context.Context, action Action) (Action, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idemKey := storeKey(action.TenantRef, action.IdempotencyKey)
	if existingRef, ok := s.byIdem[idemKey]; ok {
		existing := s.actions[storeKey(action.TenantRef, existingRef)]
		if existing.Capability != action.Capability || existing.ParameterHash != action.ParameterHash || existing.BusinessContextRef != action.BusinessContextRef {
			return Action{}, false, ErrIdempotencyConflict
		}
		return existing, false, nil
	}
	s.actions[storeKey(action.TenantRef, action.ActionRef)] = action
	s.byIdem[idemKey] = action.ActionRef
	return action, true, nil
}

func (s *MemoryStore) GetByIdempotencyKey(_ context.Context, tenantRef, idempotencyKey string) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	actionRef, ok := s.byIdem[storeKey(tenantRef, idempotencyKey)]
	if !ok {
		return Action{}, ErrNotFound
	}
	return s.actions[storeKey(tenantRef, actionRef)], nil
}

func (s *MemoryStore) GetAction(_ context.Context, tenantRef, actionRef string) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	action, ok := s.actions[storeKey(tenantRef, actionRef)]
	if !ok {
		return Action{}, ErrNotFound
	}
	return action, nil
}

func (s *MemoryStore) Grant(_ context.Context, action Action, grant Grant) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(action.TenantRef, action.ActionRef)
	stored, ok := s.actions[key]
	if !ok {
		return Action{}, ErrNotFound
	}
	if !canTransition(stored.Status, StatusGranted) {
		return Action{}, ErrForbiddenTransition
	}
	if _, exists := s.grants[key]; exists {
		return Action{}, ErrEvidenceConsumed
	}
	s.grants[key] = grant
	stored.Status = StatusGranted
	stored.GrantRef = grant.GrantRef
	stored.ApprovalEvidenceRef = action.ApprovalEvidenceRef
	stored.UpdatedAt = grant.IssuedAt
	s.actions[key] = stored
	return stored, nil
}

func (s *MemoryStore) Dispatch(_ context.Context, tenantRef, actionRef string, dispatch Dispatch, at time.Time) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(tenantRef, actionRef)
	stored, ok := s.actions[key]
	if !ok {
		return Action{}, ErrNotFound
	}
	if !canTransition(stored.Status, StatusDispatched) {
		return Action{}, ErrForbiddenTransition
	}
	grant, ok := s.grants[key]
	if !ok {
		return Action{}, ErrNotFound
	}
	// tickets.ConsumeActionGrant is the single one-use-consumption authority the
	// actions service and this in-process store share (the PostgresStore
	// expresses the identical rule transactionally via SQL + the
	// guard_action_grant_consume trigger instead, for atomicity with the outbox
	// write): a grant already consumed, or expired, cannot dispatch.
	stepGrant := runtime.StepGrant{
		GrantRef:           grant.GrantRef,
		BusinessContextRef: grant.BusinessContextRef,
		Capability:         grant.Capability,
		ParameterHash:      grant.ParameterHash,
		OneUse:             grant.OneUse,
		IssuedAt:           grant.IssuedAt,
		ExpiresAt:          grant.ExpiresAt,
	}
	if err := tickets.ConsumeActionGrant(stepGrant, at, !grant.ConsumedAt.IsZero()); err != nil {
		if errors.Is(err, tickets.ErrActionGrantConsumed) {
			return Action{}, ErrEvidenceConsumed
		}
		return Action{}, errors.Join(ErrForbiddenTransition, err)
	}
	grant.ConsumedAt = at
	s.grants[key] = grant
	s.dispatches[storeKey(tenantRef, dispatch.DispatchRef)] = dispatch
	stored.Status = StatusDispatched
	stored.UpdatedAt = at
	s.actions[key] = stored
	return stored, nil
}

func (s *MemoryStore) Transition(_ context.Context, tenantRef, actionRef string, from, to runtime.ActionStatus, reason string, at time.Time) (Action, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(tenantRef, actionRef)
	stored, ok := s.actions[key]
	if !ok {
		return Action{}, ErrNotFound
	}
	if stored.Status != from {
		return Action{}, ErrForbiddenTransition
	}
	if !canTransition(from, to) {
		return Action{}, ErrForbiddenTransition
	}
	stored.Status = to
	if reason != "" {
		stored.FailureReason = reason
	}
	stored.UpdatedAt = at
	s.actions[key] = stored
	return stored, nil
}

func (s *MemoryStore) IngestResult(_ context.Context, result Result, to runtime.ActionStatus, at time.Time) (Action, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inboxKey := storeKey(result.TenantRef, result.ResultID)
	if s.inbox[inboxKey] {
		return s.actions[storeKey(result.TenantRef, result.ActionRef)], false, nil
	}
	key := storeKey(result.TenantRef, result.ActionRef)
	stored, ok := s.actions[key]
	if !ok {
		return Action{}, false, ErrNotFound
	}
	if !canTransition(stored.Status, to) {
		return Action{}, false, ErrForbiddenTransition
	}
	s.inbox[inboxKey] = true
	s.receipts[storeKey(result.TenantRef, result.Receipt.ReceiptRef)] = result.Receipt
	stored.Status = to
	stored.ReceiptRef = result.Receipt.ReceiptRef
	stored.UpdatedAt = at
	s.actions[key] = stored
	return stored, true, nil
}

func (s *MemoryStore) ResultApplied(_ context.Context, tenantRef, resultID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inbox[storeKey(tenantRef, resultID)], nil
}

func (s *MemoryStore) GetReceipt(_ context.Context, tenantRef, receiptRef string) (runtime.ActionReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, ok := s.receipts[storeKey(tenantRef, receiptRef)]
	if !ok {
		return runtime.ActionReceipt{}, ErrNotFound
	}
	return receipt, nil
}

func (s *MemoryStore) PendingDispatches(_ context.Context, tenantRef string, limit int) ([]Dispatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Dispatch
	for _, dispatch := range s.dispatches {
		if dispatch.TenantRef == tenantRef && !dispatch.Published {
			out = append(out, dispatch)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) MarkDispatchPublished(_ context.Context, tenantRef, dispatchRef string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(tenantRef, dispatchRef)
	dispatch, ok := s.dispatches[key]
	if !ok {
		return ErrNotFound
	}
	dispatch.Published = true
	dispatch.PublishedAt = at
	s.dispatches[key] = dispatch
	return nil
}

// Grants returns a snapshot of stored grants (test observability).
func (s *MemoryStore) Grants() []Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Grant, 0, len(s.grants))
	for _, grant := range s.grants {
		out = append(out, grant)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantRef < out[j].GrantRef })
	return out
}

// MemoryEvidenceConsumer is an in-memory EvidenceConsumer for unit tests. It
// enforces the one-shot consume gate (a second consume fails ErrEvidenceConsumed).
type MemoryEvidenceConsumer struct {
	mu       sync.Mutex
	records  map[string]ConsumedEvidence // tenant/plan_ref
	consumed map[string]bool             // tenant/plan_ref
	revoked  map[string]bool             // tenant/plan_ref
}

// NewMemoryEvidenceConsumer builds an empty in-memory evidence consumer.
func NewMemoryEvidenceConsumer() *MemoryEvidenceConsumer {
	return &MemoryEvidenceConsumer{records: map[string]ConsumedEvidence{}, consumed: map[string]bool{}, revoked: map[string]bool{}}
}

// Seed records a validated (not-yet-consumed) evidence binding for plan_ref.
func (c *MemoryEvidenceConsumer) Seed(tenantRef string, evidence ConsumedEvidence) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[storeKey(tenantRef, evidence.PlanRef)] = evidence
}

// Revoke marks the transmission of plan_ref revoked (evidence becomes unusable).
func (c *MemoryEvidenceConsumer) Revoke(tenantRef, planRef string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[storeKey(tenantRef, planRef)] = true
}

func (c *MemoryEvidenceConsumer) ConsumeApprovalEvidence(_ context.Context, tenantRef, planRef string, _ time.Time) (ConsumedEvidence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := storeKey(tenantRef, planRef)
	if c.revoked[key] {
		return ConsumedEvidence{}, ErrEvidenceRejected
	}
	record, ok := c.records[key]
	if !ok {
		return ConsumedEvidence{}, ErrNotFound
	}
	if c.consumed[key] {
		return ConsumedEvidence{}, ErrEvidenceConsumed
	}
	c.consumed[key] = true
	return record, nil
}

// MemoryAuditSink records action audit events in memory (unit tests).
type MemoryAuditSink struct {
	mu     sync.Mutex
	events []AuditEvent
	fail   error
	minted int
}

// NewMemoryAuditSink builds an empty in-memory audit sink.
func NewMemoryAuditSink() *MemoryAuditSink { return &MemoryAuditSink{} }

// SetFailure makes every subsequent append fail with err (nil clears).
func (s *MemoryAuditSink) SetFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

func (s *MemoryAuditSink) AppendActionAudit(_ context.Context, event AuditEvent) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return "", s.fail
	}
	s.minted++
	s.events = append(s.events, event)
	return "actionaudit_" + itoa(s.minted), nil
}

// Events returns a copy of the appended events.
func (s *MemoryAuditSink) Events() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditEvent(nil), s.events...)
}

func itoa(value int) string {
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
