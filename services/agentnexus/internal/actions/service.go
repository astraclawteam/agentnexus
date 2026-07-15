package actions

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/astraclawteam/agentnexus/sdk/go/runtime"
	"github.com/astraclawteam/agentnexus/services/agentnexus/internal/tickets"
)

// Audit action vocabulary of the durable action lineage (INTERNAL, like the
// approval-transmission lineage). Task 0G chains and signs these events; none of
// these names is a public contract name and none asserts a business Outcome.
const (
	auditActionRequested     = "action.requested"
	auditActionGranted       = "action.granted"
	auditActionDispatched    = "action.dispatched"
	auditActionExecuting     = "action.executing"
	auditActionCompleted     = "action.completed"
	auditActionResultUnknown = "action.result_unknown"
	auditActionReconciling   = "action.reconciling"
	auditActionReconciled    = "action.reconciled"
	auditActionCompensating  = "action.compensating"
	auditActionHumanTakeover = "action.human_takeover"
	auditActionCancelled     = "action.cancelled"
)

// Service is the durable controlled-execution service: the one logical Action
// state machine, one-use grant consumption, transactional outbox/inbox and the
// reconcile/compensate paths. Every transition emits mandatory (fail-closed)
// audit lineage and advances only along the frozen allowed edges.
type Service struct {
	store     Store
	audit     AuditSink
	evidence  EvidenceConsumer
	providers DecisionProviderVerifier
	receipts  ReceiptVerifier
	publisher Publisher
	logger    *slog.Logger
	now       func() time.Time
	newID     func(prefix string) string
}

// Option configures a Service.
type Option func(*Service)

// WithEvidenceConsumer wires the one-shot approval-evidence consumption gate.
func WithEvidenceConsumer(consumer EvidenceConsumer) Option {
	return func(s *Service) { s.evidence = consumer }
}

// WithDecisionProviderVerifier wires the certified-decision-provider trust gate.
func WithDecisionProviderVerifier(verifier DecisionProviderVerifier) Option {
	return func(s *Service) { s.providers = verifier }
}

// WithReceiptVerifier wires the authoritative receipt-signature verification
// (GA Task 0G). Nil ⇒ local structural verification only, never a silent pass.
func WithReceiptVerifier(verifier ReceiptVerifier) Option {
	return func(s *Service) { s.receipts = verifier }
}

// WithPublisher wires the outbox dispatch transport (NATS JetStream).
func WithPublisher(publisher Publisher) Option {
	return func(s *Service) { s.publisher = publisher }
}

// WithClock overrides the service clock.
func WithClock(clock func() time.Time) Option {
	return func(s *Service) { s.now = clock }
}

// WithIDGenerator overrides the opaque identifier generator.
func WithIDGenerator(newID func(prefix string) string) Option {
	return func(s *Service) { s.newID = newID }
}

// WithLogger overrides the service logger. Log lines carry refs, statuses and
// coded reasons only.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// NewService builds the durable action service. Store and audit are mandatory.
func NewService(store Store, audit AuditSink, opts ...Option) (*Service, error) {
	if store == nil {
		return nil, errors.New("action service requires a store")
	}
	if audit == nil {
		return nil, errors.New("action service requires an audit sink")
	}
	s := &Service{
		store:  store,
		audit:  audit,
		logger: slog.Default(),
		now:    func() time.Time { return time.Now().UTC() },
		newID:  randomOpaqueID,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Service) guard(ctx context.Context) error {
	if s == nil || s.store == nil || s.audit == nil || s.now == nil || s.newID == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrUnavailable, err)
	}
	return nil
}

// auditBinding is the set of first-class, recoverable operation bindings the
// action-transition audit records alongside the transition. The values are
// loaded from the Action record (and, for the request, the ActionRequest) so
// every binding is individually signed and inspectable - not folded
// non-recoverably into a single details hash.
type auditBinding struct {
	Capability          string
	ParameterHash       string
	GrantRef            string
	ApprovalEvidenceRef string
	ReceiptRef          string
	RiskAuthority       string
}

// bindingOf projects an Action onto its audit binding.
func bindingOf(a Action) auditBinding {
	return auditBinding{
		Capability:          a.Capability,
		ParameterHash:       a.ParameterHash,
		GrantRef:            a.GrantRef,
		ApprovalEvidenceRef: a.ApprovalEvidenceRef,
		ReceiptRef:          a.ReceiptRef,
		RiskAuthority:       a.RiskAuthority,
	}
}

// appendAudit appends one mandatory action-transition lineage event. A failed
// append fails the transition closed. The binding refs (from the Action) and the
// verified principal's Agent/org context are bound as first-class signed fields.
func (s *Service) appendAudit(ctx context.Context, principal runtime.PrincipalContext, binding auditBinding, action, actionRef string, from, to runtime.ActionStatus, details map[string]any) (string, error) {
	ref, err := s.audit.AppendActionAudit(ctx, AuditEvent{
		TenantRef:           principal.TenantRef,
		PrincipalRef:        principal.PrincipalRef,
		Action:              action,
		ActionRef:           actionRef,
		StatusFrom:          from,
		StatusTo:            to,
		Details:             details,
		Capability:          binding.Capability,
		ParameterHash:       binding.ParameterHash,
		GrantRef:            binding.GrantRef,
		ApprovalEvidenceRef: binding.ApprovalEvidenceRef,
		ReceiptRef:          binding.ReceiptRef,
		RiskAuthority:       binding.RiskAuthority,
		AgentClientRef:      principal.AgentClientRef,
		AgentReleaseRef:     principal.AgentReleaseRef,
		OrgSnapshotRef:      principal.OrgSnapshotRef,
	})
	if err != nil || ref == "" {
		return "", errors.Join(ErrUnavailable, errors.New("action audit append failed"), err)
	}
	return ref, nil
}

// verifyDecisionProvider enforces the caller trust gate before a side effect can
// be reached: a first-party caller passes; a certified third party requires the
// wired certified-decision-provider verification (nil is never a pass-stub);
// every other caller is untrusted and denied.
func (s *Service) verifyDecisionProvider(ctx context.Context, principal runtime.PrincipalContext, capability, parameterHash string) error {
	switch principal.TrustClass {
	case runtime.TrustFirstParty:
		return nil
	case runtime.TrustCertifiedThirdParty:
		if s.providers == nil {
			return errors.Join(ErrCallerUntrusted, errors.New("certified third-party action requires the wired decision-provider verification (Task 0F seam); nil wiring fails closed"))
		}
		if err := s.providers.VerifyDecisionProvider(ctx, principal.TenantRef, principal, capability, parameterHash); err != nil {
			return errors.Join(ErrCallerUntrusted, err)
		}
		return nil
	default:
		return ErrCallerUntrusted
	}
}

// RequestAction validates and persists ONE logical Action per (tenant,
// idempotency_key). A duplicate request returns the SAME Action and never
// creates a second side effect; a reused key that binds a different operation is
// rejected. An action carrying an approval plan waits in awaiting_approval;
// otherwise it rests in requested. An untrusted caller is rejected here.
func (s *Service) RequestAction(ctx context.Context, principal runtime.PrincipalContext, req runtime.ActionRequest) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	if err := req.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	if principal.TrustClass == runtime.TrustUntrusted {
		return Action{}, ErrCallerUntrusted
	}
	// Idempotent pre-check: one logical Action per (tenant, idempotency_key).
	existing, err := s.store.GetByIdempotencyKey(ctx, principal.TenantRef, req.IdempotencyKey)
	switch {
	case err == nil:
		if existing.Capability != req.Capability || existing.ParameterHash != req.ParameterHash || existing.BusinessContextRef != req.BusinessContextRef {
			return Action{}, ErrIdempotencyConflict
		}
		return existing, nil
	case !errors.Is(err, ErrNotFound):
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	now := s.now().UTC()
	actionRef := s.newID("act_")
	if runtime.ValidateHandle(actionRef, runtime.HandleAction) != nil {
		return Action{}, ErrUnavailable
	}
	status := StatusRequested
	planRef := ""
	if req.ApprovalPlanRef != nil {
		status = StatusAwaitingApproval
		planRef = req.ApprovalPlanRef.PlanRef
	}
	auditRef, err := s.appendAudit(ctx, principal, auditBinding{Capability: req.Capability, ParameterHash: req.ParameterHash, RiskAuthority: req.RiskDecision.Authority}, auditActionRequested, actionRef, "", status, map[string]any{"capability": req.Capability, "parameter_hash": req.ParameterHash})
	if err != nil {
		return Action{}, err
	}
	action := Action{
		TenantRef:             principal.TenantRef,
		ActionRef:             actionRef,
		Status:                status,
		BusinessContextRef:    req.BusinessContextRef,
		Capability:            req.Capability,
		ParameterHash:         req.ParameterHash,
		IdempotencyKey:        req.IdempotencyKey,
		RiskAuthority:         req.RiskDecision.Authority,
		RiskLevel:             req.RiskDecision.RiskLevel,
		ApprovalPlanRef:       planRef,
		CompensationRef:       req.CompensationRef,
		ExpectedReceiptSchema: req.ExpectedReceiptSchema,
		Postconditions:        req.Postconditions,
		VerificationNeeds:     req.VerificationNeeds,
		ExpiresAt:             req.ExpiresAt.UTC(),
		AuditRefID:            auditRef,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	stored, _, err := s.store.PutRequested(ctx, action)
	if err != nil {
		if errors.Is(err, ErrIdempotencyConflict) {
			return Action{}, ErrIdempotencyConflict
		}
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	return stored, nil
}

// Grant advances an action to granted: it enforces the trust gate, consumes the
// approval authority's evidence ONE-SHOT (when the action awaited approval) and
// mints the one-use grant bound to the exact operation. The minted grant is the
// SDK runtime.StepGrant shape; its persistence is atomic with the transition.
func (s *Service) Grant(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if action.Status != StatusRequested && action.Status != StatusAwaitingApproval {
		return Action{}, ErrForbiddenTransition
	}
	// The decisive trust gate: an untrusted or uncertified caller can never reach
	// a side effect. AgentNexus does not rewrite the caller's domain RiskDecision.
	if err := s.verifyDecisionProvider(ctx, principal, action.Capability, action.ParameterHash); err != nil {
		return Action{}, err
	}
	now := s.now().UTC()
	approvalEvidenceRef := ""
	if action.Status == StatusAwaitingApproval {
		if s.evidence == nil {
			return Action{}, ErrApprovalRequired
		}
		consumed, err := s.evidence.ConsumeApprovalEvidence(ctx, principal.TenantRef, action.ApprovalPlanRef, now)
		if err != nil {
			switch {
			case errors.Is(err, ErrEvidenceConsumed):
				return Action{}, ErrEvidenceConsumed
			case errors.Is(err, ErrEvidenceRejected), errors.Is(err, ErrNotFound):
				return Action{}, ErrEvidenceRejected
			}
			return Action{}, errors.Join(ErrUnavailable, err)
		}
		// Exact operation binding: the approved decision must name this action's
		// capability + parameter hash and be an approval (not a denial/narrowing).
		if consumed.Capability != action.Capability || consumed.ParameterHash != action.ParameterHash || consumed.Decision != runtime.ApprovalApproved {
			return Action{}, ErrEvidenceRejected
		}
		approvalEvidenceRef = consumed.ApprovalRef
	}
	grantRef := s.newID("grant_")
	stepGrant, err := tickets.MintActionGrant(tickets.ActionGrantInput{
		GrantRef:           grantRef,
		BusinessContextRef: action.BusinessContextRef,
		Capability:         action.Capability,
		ParameterHash:      action.ParameterHash,
		TTL:                maxActionGrantTTL,
	}, now)
	if err != nil {
		return Action{}, errors.Join(ErrUnavailable, err)
	}
	grantBinding := bindingOf(action)
	grantBinding.GrantRef = grantRef
	grantBinding.ApprovalEvidenceRef = approvalEvidenceRef
	if _, err := s.appendAudit(ctx, principal, grantBinding, auditActionGranted, actionRef, action.Status, StatusGranted, map[string]any{"grant_ref": grantRef}); err != nil {
		return Action{}, err
	}
	action.ApprovalEvidenceRef = approvalEvidenceRef
	grant := Grant{
		TenantRef:          principal.TenantRef,
		GrantRef:           grantRef,
		ActionRef:          actionRef,
		BusinessContextRef: action.BusinessContextRef,
		Capability:         action.Capability,
		ParameterHash:      action.ParameterHash,
		OneUse:             true,
		IssuedAt:           stepGrant.IssuedAt,
		ExpiresAt:          stepGrant.ExpiresAt,
	}
	granted, err := s.store.Grant(ctx, action, grant)
	if err != nil {
		return Action{}, mapTransitionErr(err)
	}
	return granted, nil
}

// Dispatch advances granted -> dispatched: it consumes the one-use grant and
// writes the durable outbox row in one transaction BEFORE any publish. A blind
// re-dispatch of an already-dispatched or result-unknown action is forbidden.
func (s *Service) Dispatch(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if action.Status != StatusGranted {
		switch action.Status {
		case StatusDispatched, StatusExecuting, StatusResultUnknown, StatusReconciling:
			return Action{}, ErrBlindRetryForbidden
		}
		return Action{}, ErrForbiddenTransition
	}
	now := s.now().UTC()
	dispatchRef := s.newID("dsp_")
	if _, err := s.appendAudit(ctx, principal, bindingOf(action), auditActionDispatched, actionRef, StatusGranted, StatusDispatched, map[string]any{"grant_ref": action.GrantRef, "dispatch_ref": dispatchRef}); err != nil {
		return Action{}, err
	}
	dispatch := Dispatch{
		TenantRef:     principal.TenantRef,
		DispatchRef:   dispatchRef,
		ActionRef:     actionRef,
		Capability:    action.Capability,
		ParameterHash: action.ParameterHash,
		GrantRef:      action.GrantRef,
		Kind:          DispatchExecute,
		CreatedAt:     now,
	}
	dispatched, err := s.store.Dispatch(ctx, principal.TenantRef, actionRef, dispatch, now)
	if err != nil {
		return Action{}, mapTransitionErr(err)
	}
	return dispatched, nil
}

// MarkExecuting advances dispatched -> executing when the connector host picks
// up the dispatch.
func (s *Service) MarkExecuting(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	return s.simpleTransition(ctx, principal, actionRef, StatusDispatched, StatusExecuting, auditActionExecuting, "")
}

// IngestReceipt applies one connector-reported execution result exactly once
// (inbox dedup by resultID) and completes the action to the receipt's TECHNICAL
// terminal status. Only a receipt that binds the exact action (action_ref +
// parameter_hash + capability), matches the declared ExpectedReceiptSchema and
// passes the ReceiptVerifier seam completes an Action.
func (s *Service) IngestReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	if resultID == "" {
		return Action{}, errors.Join(ErrInvalidInput, errors.New("connector result id is required for inbox dedup"))
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, receipt.ActionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	to, err := s.verifyReceipt(ctx, principal.TenantRef, action, receipt)
	if err != nil {
		return Action{}, err
	}
	// Guard-then-audit (the systemic 0F pattern, mirroring Grant/Dispatch/
	// transition): the action.completed audit event — which GA Task 0G signs and
	// independently verifies — is emitted EXACTLY ONCE per genuine completion and
	// NEVER for a deduped redelivery or a rejected receipt. So the
	// legality/dedup determination happens BEFORE any appendAudit.
	switch action.Status {
	case StatusExecuting, StatusDispatched:
		// A genuine first completion: the action is not yet terminal, so this
		// result_id has not been applied (applying it makes the action terminal).
		return s.completeFromReceipt(ctx, principal, resultID, receipt, to, action)
	case StatusSucceeded, StatusFailed:
		// The action is already terminal. Distinguish an idempotent DUPLICATE
		// (the same result_id already landed -> no-op, no audit) from an
		// out-of-order DIFFERENT receipt (this result_id never applied -> rejected,
		// no audit). result_id is the inbox dedup key.
		applied, err := s.store.ResultApplied(ctx, principal.TenantRef, resultID)
		if err != nil {
			return Action{}, errors.Join(ErrUnavailable, err)
		}
		if applied {
			return action, nil
		}
		return Action{}, ErrForbiddenTransition
	default:
		return Action{}, ErrForbiddenTransition
	}
}

// completeFromReceipt applies one genuine completion: it audits the completion
// exactly once (the from-status is already known legal by the caller's guard),
// then persists it. A concurrent redelivery racing this apply is deduped by the
// store's inbox (ok=false) — the same at-most-one-spurious-audit-under-store-
// contention window every other 0F transition (Grant/Dispatch) already has.
func (s *Service) completeFromReceipt(ctx context.Context, principal runtime.PrincipalContext, resultID string, receipt runtime.ActionReceipt, to runtime.ActionStatus, action Action) (Action, error) {
	completeBinding := bindingOf(action)
	completeBinding.ReceiptRef = receipt.ReceiptRef
	if _, err := s.appendAudit(ctx, principal, completeBinding, auditActionCompleted, action.ActionRef, action.Status, to, map[string]any{"receipt_ref": receipt.ReceiptRef, "result_id": resultID}); err != nil {
		return Action{}, err
	}
	result := Result{TenantRef: principal.TenantRef, ResultID: resultID, ActionRef: receipt.ActionRef, Receipt: receipt}
	applied, _, err := s.store.IngestResult(ctx, result, to, s.now().UTC())
	if err != nil {
		return Action{}, mapTransitionErr(err)
	}
	return applied, nil
}

// verifyReceipt is the completion seam. The local structural checks are the
// floor (exact action/parameter/capability binding, schema match, terminal
// technical status, result-hash integrity). A nil ReceiptVerifier NEVER weakens
// them and never substitutes a silent pass for a wired rejection; a wired
// verifier (Task 0G) additionally verifies the receipt signature.
func (s *Service) verifyReceipt(ctx context.Context, tenantRef string, action Action, receipt runtime.ActionReceipt) (runtime.ActionStatus, error) {
	if err := receipt.Validate(); err != nil {
		return "", errors.Join(ErrReceiptRejected, err)
	}
	if receipt.ActionRef != action.ActionRef || receipt.ParameterHash != action.ParameterHash || receipt.Capability != action.Capability {
		return "", errors.Join(ErrReceiptRejected, errors.New("receipt does not bind the exact action operation"))
	}
	if receipt.ReceiptSchema != action.ExpectedReceiptSchema {
		return "", errors.Join(ErrReceiptRejected, errors.New("receipt schema does not match the declared expected receipt schema"))
	}
	to, ok := terminalReceiptStatus(receipt.Status)
	if !ok {
		return "", errors.Join(ErrReceiptRejected, errors.New("only a technical succeeded/failed receipt completes an action; the runtime never asserts a business outcome"))
	}
	// Fail CLOSED: only a VERIFIED signed receipt completes an Action. With no
	// verifier wired the signature cannot be checked, so an unverifiable receipt
	// never completes (mirroring the audit path's hard failure) - the local
	// structural checks are the floor, never a substitute for authenticity.
	if s.receipts == nil {
		return "", errors.Join(ErrReceiptRejected, errors.New("no receipt verifier wired; an unverifiable receipt cannot complete an action"))
	}
	if err := s.receipts.VerifyReceipt(ctx, tenantRef, receipt); err != nil {
		return "", errors.Join(ErrReceiptRejected, err)
	}
	return to, nil
}

// MarkResultUnknown advances dispatched|executing -> result_unknown on a
// connector timeout AFTER the side effect may already have executed. Blind retry
// is forbidden from result_unknown; the only path forward is reconciliation.
func (s *Service) MarkResultUnknown(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if action.Status != StatusExecuting && action.Status != StatusDispatched {
		return Action{}, ErrForbiddenTransition
	}
	return s.transition(ctx, principal, bindingOf(action), action.ActionRef, action.Status, StatusResultUnknown, auditActionResultUnknown, "connector timeout after possible execution")
}

// HumanTakeover escalates any live action to human_takeover.
func (s *Service) HumanTakeover(ctx context.Context, principal runtime.PrincipalContext, actionRef, reason string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if !canTransition(action.Status, StatusHumanTakeover) {
		return Action{}, ErrForbiddenTransition
	}
	return s.transition(ctx, principal, bindingOf(action), action.ActionRef, action.Status, StatusHumanTakeover, auditActionHumanTakeover, reason)
}

// Cancel handles cancellation deterministically: before dispatch (no side effect
// yet) it fails the action cleanly; after dispatch (a side effect may have run)
// it escalates to human takeover rather than silently "cancelling".
func (s *Service) Cancel(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	switch action.Status {
	case StatusRequested, StatusAwaitingApproval, StatusGranted:
		return s.transition(ctx, principal, bindingOf(action), action.ActionRef, action.Status, StatusFailed, auditActionCancelled, "cancelled before dispatch")
	case StatusDispatched, StatusExecuting, StatusResultUnknown, StatusReconciling:
		return s.transition(ctx, principal, bindingOf(action), action.ActionRef, action.Status, StatusHumanTakeover, auditActionCancelled, "cancelled after dispatch; escalated to human takeover")
	}
	return Action{}, ErrForbiddenTransition
}

// GetAction returns one action for the caller's tenant.
func (s *Service) GetAction(ctx context.Context, principal runtime.PrincipalContext, actionRef string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	return action, nil
}

// GetReceipt returns the persisted receipt of one action for the caller's tenant.
func (s *Service) GetReceipt(ctx context.Context, principal runtime.PrincipalContext, receiptRef string) (runtime.ActionReceipt, error) {
	if err := s.guard(ctx); err != nil {
		return runtime.ActionReceipt{}, err
	}
	if err := principal.Validate(); err != nil {
		return runtime.ActionReceipt{}, errors.Join(ErrInvalidInput, err)
	}
	receipt, err := s.store.GetReceipt(ctx, principal.TenantRef, receiptRef)
	if err != nil {
		return runtime.ActionReceipt{}, mapGetErr(err)
	}
	return receipt, nil
}

// simpleTransition audits and applies a plain from->to edge.
func (s *Service) simpleTransition(ctx context.Context, principal runtime.PrincipalContext, actionRef string, from, to runtime.ActionStatus, auditAction, reason string) (Action, error) {
	if err := s.guard(ctx); err != nil {
		return Action{}, err
	}
	if err := principal.Validate(); err != nil {
		return Action{}, errors.Join(ErrInvalidInput, err)
	}
	action, err := s.store.GetAction(ctx, principal.TenantRef, actionRef)
	if err != nil {
		return Action{}, mapGetErr(err)
	}
	if action.Status != from {
		return Action{}, ErrForbiddenTransition
	}
	return s.transition(ctx, principal, bindingOf(action), actionRef, from, to, auditAction, reason)
}

// transition audits then applies one allowed edge with no side rows.
func (s *Service) transition(ctx context.Context, principal runtime.PrincipalContext, binding auditBinding, actionRef string, from, to runtime.ActionStatus, auditAction, reason string) (Action, error) {
	if !canTransition(from, to) {
		return Action{}, ErrForbiddenTransition
	}
	if _, err := s.appendAudit(ctx, principal, binding, auditAction, actionRef, from, to, map[string]any{"reason": reason}); err != nil {
		return Action{}, err
	}
	updated, err := s.store.Transition(ctx, principal.TenantRef, actionRef, from, to, reason, s.now().UTC())
	if err != nil {
		return Action{}, mapTransitionErr(err)
	}
	return updated, nil
}

func mapGetErr(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	return errors.Join(ErrUnavailable, err)
}

func mapTransitionErr(err error) error {
	switch {
	case errors.Is(err, ErrForbiddenTransition):
		return ErrForbiddenTransition
	case errors.Is(err, ErrEvidenceConsumed):
		return ErrEvidenceConsumed
	case errors.Is(err, ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	case errors.Is(err, ErrNotFound):
		return ErrNotFound
	}
	return errors.Join(ErrUnavailable, err)
}
